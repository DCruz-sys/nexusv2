"""WebSocket chat endpoint and chat history API."""
from __future__ import annotations

import asyncio
import json
import re
import uuid
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from app.ai.agent_swarm import agent_swarm
from app.ai.memory_manager import memory_manager
from app.ai.model_router import model_router
from app.ai.prompts import get_agent_prompt
from app.config import (
    CHAT_AUTO_ALLOWLIST_DOMAINS,
    CHAT_AUTO_ALLOWLIST_ENABLED,
    LEARNING_DEFAULT_PROFILE,
    LEARNING_SOURCE_BATCH_SIZE,
    MAX_PENDING_CRAWL,
    ENABLE_CRAWLER,
    MAX_PENDING_SCANS,
    MEMORY_CHAT_SCOPE,
    MEMORY_RETRIEVAL_LIMIT,
)
from app.database import (
    add_memory_audit_event,
    add_target_rule,
    count_pending_jobs,
    create_scan,
    enqueue_job,
    get_chat_history,
    save_chat_message,
    upsert_learning_frontier_url,
    upsert_learning_source,
    update_scan,
)
from app.security.allowlist import TargetNotAllowedError, match_any_domain_pattern, parse_target, require_target_allowed
from app.security.auth import authenticate_websocket, require_viewer
from app.services.scan_events import broadcast_scan_event

router = APIRouter(tags=["chat"])

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"\bhttps?://[^\s]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")
_SESSION_RE = re.compile(r"^[a-zA-Z0-9._:-]{6,128}$")


def _normalize_scan_type(text: str) -> str:
    lowered = (text or "").lower()
    if "full" in lowered:
        return "full"
    if "quick" in lowered:
        return "quick"
    return "quick"


def _normalize_methodology(text: str) -> str:
    lowered = (text or "").lower()
    if "mitre" in lowered or "attack" in lowered:
        return "mitre"
    if "killchain" in lowered or "kill chain" in lowered:
        return "killchain"
    if "ai" in lowered:
        return "ai"
    return "owasp"


def _extract_target(text: str) -> Optional[str]:
    if not text:
        return None
    for regex in (_URL_RE, _IP_RE, _DOMAIN_RE):
        match = regex.search(text)
        if match:
            return match.group(0).strip(".,)")
    return None


def _normalize_seed_url(raw: str) -> str:
    value = (raw or "").strip().strip(".,)")
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        return ""
    if not parsed.netloc:
        return ""
    return parsed.geturl()


def _normalize_session_id(raw: object) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    if not _SESSION_RE.match(value):
        return ""
    return value


async def _llm_parse_scan_params(user_msg: str) -> dict:
    parse_task = (
        "Extract scan parameters from this message and return JSON only in this format: "
        '{"target":"...", "methodology":"owasp|ai|mitre|killchain", "scan_type":"full|quick"}. '
        f"Message: {user_msg!r}"
    )
    result = await agent_swarm.agents["coordinator"].execute(parse_task)
    raw = str(result.get("response", ""))
    start = raw.find("{")
    end = raw.rfind("}") + 1
    if start < 0 or end <= start:
        return {}
    parsed = json.loads(raw[start:end])
    return parsed if isinstance(parsed, dict) else {}


async def _queue_scan_from_chat(user_msg: str) -> tuple[str, str]:
    params = {
        "target": _extract_target(user_msg),
        "methodology": _normalize_methodology(user_msg),
        "scan_type": _normalize_scan_type(user_msg),
    }
    if not params["target"]:
        llm_params = await _llm_parse_scan_params(user_msg)
        if llm_params:
            params.update(llm_params)

    target = str(params.get("target") or "").strip()
    if not target or target == "...":
        raise ValueError("missing_target")

    try:
        await require_target_allowed(target, actor="chat", reason="chat_scan_request")
    except TargetNotAllowedError as exc:
        if not CHAT_AUTO_ALLOWLIST_ENABLED:
            raise
        info = parse_target(target)
        host = info.host
        matched = match_any_domain_pattern(host, CHAT_AUTO_ALLOWLIST_DOMAINS)
        if not matched:
            raise TargetNotAllowedError(
                f"Target '{target}' is outside allowed scope. Domain '{host}' is not approved for chat auto-allowlist. "
                "Add it to Targets first, or add it to CHAT_AUTO_ALLOWLIST_DOMAINS."
            ) from exc

        rule_id = None
        try:
            rule_id = await add_target_rule(rule_type="domain", pattern=host, created_by="chat", enabled=True)
            await add_memory_audit_event(
                event_type="chat_auto_allowlist",
                actor="chat",
                session_id=None,
                reason="chat_auto_allowlist",
                payload={"host": host, "matched_pattern": matched, "rule_id": rule_id, "target": target},
            )
        except Exception:
            # Never block scans on allowlist/audit logging failures.
            rule_id = rule_id or None

        await require_target_allowed(target, actor="chat", reason="chat_scan_request_auto_allowlist")

    pending = await count_pending_jobs("scan")
    if pending >= MAX_PENDING_SCANS:
        raise RuntimeError(f"queue_full:{pending}")

    methodology = _normalize_methodology(str(params.get("methodology") or "owasp"))
    scan_type = _normalize_scan_type(str(params.get("scan_type") or "full"))
    scan_id = str(uuid.uuid4())

    await create_scan(scan_id, target, scan_type, methodology, {})
    await update_scan(scan_id, status="queued", progress=0)
    job_id = await enqueue_job(
        job_type="scan",
        payload={
            "scan_id": scan_id,
            "target": target,
            "methodology": methodology,
            "scan_type": scan_type,
            "config": {},
        },
        max_attempts=2,
    )
    await broadcast_scan_event(scan_id, {"type": "queued", "scan_id": scan_id, "job_id": job_id, "progress": 0})
    msg = (
        "Scan queued.\n\n"
        f"- Target: `{target}`\n"
        f"- Methodology: `{methodology.upper()}`\n"
        f"- Type: `{scan_type.capitalize()}`\n"
        f"- Scan ID: `{scan_id}`\n"
        f"- Job ID: `{job_id}`\n\n"
        "Live progress is available in the Scans dashboard."
    )
    return msg, scan_id


@router.websocket("/ws/chat")
async def chat_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time AI chat with streaming responses."""
    _principal = await authenticate_websocket(websocket, required_role="operator")
    if not _principal:
        return
    await websocket.accept()
    session_id = str(uuid.uuid4())
    await websocket.send_json({"type": "session", "session_id": session_id})
    durable_to_global = MEMORY_CHAT_SCOPE == "global"

    try:
        while True:
            data = await websocket.receive_json()
            user_msg = data.get("message", "")
            force_model = data.get("model", None)
            sid = _normalize_session_id(data.get("session_id", session_id))
            if sid:
                session_id = sid
            elif data.get("session_id") not in (None, "", session_id):
                await add_memory_audit_event(
                    event_type="chat_session_id_rejected",
                    actor="chat",
                    session_id=session_id,
                    reason="invalid_session_id_format",
                    payload={"provided": str(data.get("session_id", ""))[:160]},
                )
            if not user_msg:
                continue

            await save_chat_message(session_id, "user", user_msg)

            remember_match = re.match(r"^\s*(?:/remember|remember)\s*:\s*(.+)$", user_msg, flags=re.IGNORECASE)
            if remember_match:
                learned_fact = remember_match.group(1).strip()
                memory_id = await memory_manager.teach(
                    session_id=None if durable_to_global else session_id,
                    content=learned_fact,
                    memory_type="procedural",
                    importance=0.9,
                    metadata={"source": "user_directive"},
                )
                ack = (
                    "Saved to long-term memory.\n\n"
                    f"- Memory ID: `{memory_id or 'updated-existing'}`\n"
                    f"- Fact: `{learned_fact[:200]}`"
                )
                await websocket.send_json({"type": "meta", "model": "memory-manager", "task_type": "memory_write"})
                await websocket.send_json({"type": "stream_start"})
                await websocket.send_json({"type": "token", "content": ack})
                await websocket.send_json({"type": "stream_end"})
                await save_chat_message(
                    session_id,
                    "assistant",
                    ack,
                    model_used="memory-manager",
                    task_type="memory_write",
                )
                continue

            learn_match = re.match(r"^\s*/learn\s+(.+)$", user_msg, flags=re.IGNORECASE)
            if not learn_match:
                learn_match = re.match(r"^\s*(?:/learn|learn)\s*:\s*(.+)$", user_msg, flags=re.IGNORECASE)
            if learn_match:
                if not ENABLE_CRAWLER:
                    msg = "Crawler is disabled by feature flag."
                else:
                    seed_raw = _extract_target(learn_match.group(1)) or learn_match.group(1).strip()
                    seed_url = _normalize_seed_url(seed_raw)
                    if not seed_url:
                        msg = "Invalid learn URL. Example: `/learn https://book.hacktricks.wiki`"
                    else:
                        pending = await count_pending_jobs("crawl_source")
                        if pending >= MAX_PENDING_CRAWL:
                            msg = f"Learning source queue is full ({pending}/{MAX_PENDING_CRAWL})."
                        else:
                            source = await upsert_learning_source(
                                seed_url=seed_url,
                                profile=LEARNING_DEFAULT_PROFILE,
                                enabled=True,
                                metadata={"created_via": "chat", "session_id": session_id},
                            )
                            source_id = str(source.get("id") or "")
                            domain = str(source.get("domain") or "")
                            await upsert_learning_frontier_url(
                                source_id=source_id,
                                url=seed_url,
                                domain=domain,
                                depth=0,
                                priority=100,
                                discovered_from=seed_url,
                            )
                            job_id = await enqueue_job(
                                job_type="crawl_source",
                                payload={
                                    "trigger": "chat",
                                    "source_id": source_id,
                                    "batch_size": LEARNING_SOURCE_BATCH_SIZE,
                                },
                                max_attempts=2,
                            )
                            await memory_manager.remember(
                                content=f"Learning seed added: {seed_url}",
                                summary=f"Learning seed: {seed_url}"[:220],
                                memory_type="semantic",
                                source_type="crawl_seed",
                                session_id=None if durable_to_global else session_id,
                                source_id=job_id,
                                metadata={"seed_url": seed_url, "trigger": "chat"},
                                importance=0.7,
                                confidence=0.9,
                                reason="chat_learn_seed",
                            )
                            msg = (
                                "Autonomous learning source registered.\n\n"
                                f"- Seed: `{seed_url}`\n"
                                f"- Source ID: `{source_id}`\n"
                                f"- Job ID: `{job_id}`\n\n"
                                "Mode: strict same-domain deep crawl, resumable frontier, automatic background distillation."
                            )

                await websocket.send_json({"type": "meta", "model": "crawler", "task_type": "learn"})
                await websocket.send_json({"type": "stream_start"})
                await websocket.send_json({"type": "token", "content": msg})
                await websocket.send_json({"type": "stream_end"})
                await save_chat_message(
                    session_id,
                    "assistant",
                    msg,
                    model_used="crawler",
                    task_type="learn",
                )
                continue

            try:
                memory_bundle = await memory_manager.retrieve_context(
                    session_id=session_id,
                    query=user_msg,
                    limit=MEMORY_RETRIEVAL_LIMIT,
                )
            except Exception:
                memory_bundle = {"context": "", "items": []}

            persistent_context = memory_bundle.get("context", "")
            history = await get_chat_history(session_id, limit=20)
            messages = get_agent_prompt("chat", context=persistent_context)
            for row in history:
                messages.append({"role": row["role"], "content": row["content"]})

            model_key, task_type = model_router.route(user_msg, force_model)

            if task_type == "scan":
                await websocket.send_json({"type": "meta", "model": "coordinator", "task_type": "scan"})
                try:
                    queued_msg, _scan_id = await _queue_scan_from_chat(user_msg)
                    await websocket.send_json({"type": "stream_start"})
                    await websocket.send_json({"type": "token", "content": queued_msg})
                    await websocket.send_json({"type": "stream_end"})
                    await save_chat_message(
                        session_id,
                        "assistant",
                        queued_msg,
                        model_used="coordinator",
                        task_type="scan",
                    )
                    asyncio.create_task(memory_manager.ingest_chat_turn(
                        session_id=session_id,
                        user_message=user_msg,
                        assistant_message=queued_msg,
                        task_type="scan",
                        model_used="coordinator",
                        durable_to_global=durable_to_global,
                    ))
                    continue
                except ValueError:
                    msg = (
                        "I detected a scan request but no target was found. "
                        "Provide a URL/IP, for example: `scan https://example.com quick`"
                    )
                except TargetNotAllowedError as exc:
                    msg = str(exc)
                except RuntimeError as exc:
                    msg = str(exc)
                    if msg.startswith("queue_full:"):
                        pending = msg.split(":", 1)[1]
                        msg = f"Scan queue is full ({pending}/{MAX_PENDING_SCANS}). Try again later."
                except Exception as exc:
                    msg = f"Failed to queue scan: {exc}"

                await websocket.send_json({"type": "stream_start"})
                await websocket.send_json({"type": "token", "content": msg})
                await websocket.send_json({"type": "stream_end"})
                await save_chat_message(
                    session_id,
                    "assistant",
                    msg,
                    model_used="coordinator",
                    task_type="scan_error",
                )
                asyncio.create_task(memory_manager.ingest_chat_turn(
                    session_id=session_id,
                    user_message=user_msg,
                    assistant_message=msg,
                    task_type="scan_error",
                    model_used="coordinator",
                    durable_to_global=durable_to_global,
                ))
                continue

            await websocket.send_json({
                "type": "meta",
                "model": model_key,
                "task_type": task_type,
                "memory_hits": len(memory_bundle.get("items", [])),
            })

            full_response = ""
            await websocket.send_json({"type": "stream_start"})
            async for token in model_router.stream_query(messages=messages, force_model=force_model):
                full_response += token
                await websocket.send_json({"type": "token", "content": token})
            await websocket.send_json({"type": "stream_end"})

            await save_chat_message(
                session_id,
                "assistant",
                full_response,
                model_used=model_key,
                task_type=task_type,
            )
            asyncio.create_task(memory_manager.ingest_chat_turn(
                session_id=session_id,
                user_message=user_msg,
                assistant_message=full_response,
                task_type=task_type,
                model_used=model_key,
                durable_to_global=durable_to_global,
            ))
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass


@router.get("/chat/history/{session_id}")
async def api_chat_history(session_id: str, limit: int = 50, _principal=Depends(require_viewer)):
    """Get chat history for a session."""
    history = await get_chat_history(session_id, limit)
    return {"session_id": session_id, "messages": history}
