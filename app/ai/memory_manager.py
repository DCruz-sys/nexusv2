"""Persistent memory manager for long-term agent memory."""
import asyncio
import hashlib
import json
import math
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.ai.accelerators import rank_memory_candidates
from app.ai.model_router import model_router
from app.ai.nim_retrieval_client import nim_retrieval_client
from app.config import (
    KB_RERANK_ENABLED,
    KB_RERANK_MODEL,
    KB_RETRIEVAL_CANDIDATES,
    KB_RETRIEVAL_LIMIT,
    MEMORY_AUTO_MAINTENANCE,
    MEMORY_CANDIDATE_LIMIT,
    MEMORY_DECAY_DAYS,
    MEMORY_ENABLE_NIM_EXTRACTION,
    MEMORY_EXTRACTION_MODEL,
    MEMORY_MAINTENANCE_INTERVAL_MIN,
    MEMORY_MAX_ITEMS,
    MEMORY_MIN_SCORE,
    MEMORY_RETRIEVAL_LIMIT,
    MEMORY_WRITE_SECRET,
)
from app.database import (
    add_memory_audit_event,
    add_memory_item,
    delete_memory_items,
    get_memory_candidates,
    get_memory_stats,
    increment_memory_recall,
    list_memory_items,
    list_memory_sessions,
    search_crawl_passages_fts,
    save_memory_checkpoint,
)

STOPWORDS = {
    "the", "and", "for", "with", "this", "that", "from", "have", "has", "are",
    "was", "were", "you", "your", "our", "their", "then", "than", "into", "about",
    "what", "when", "where", "which", "will", "would", "could", "should", "please",
    "also", "just", "into", "onto", "over", "under", "http", "https",
}


def _extract_json_object(raw_text: str) -> Optional[dict]:
    if not raw_text:
        return None
    start = raw_text.find("{")
    end = raw_text.rfind("}")
    if start < 0 or end < 0 or end <= start:
        return None
    try:
        parsed = json.loads(raw_text[start:end + 1])
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


class MemoryManager:
    """Handles memory retrieval, long-term writes, consolidation, and checkpoints."""

    def __init__(self):
        self._maintenance_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        self._last_consolidation: dict[str, float] = {}

    @staticmethod
    def _safe_ts(iso_dt: Optional[str]) -> float:
        if not iso_dt:
            return time.time()
        try:
            return datetime.fromisoformat(iso_dt).timestamp()
        except Exception:
            return time.time()

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        words = re.findall(r"[a-zA-Z0-9_./:-]+", (text or "").lower())
        return {w for w in words if len(w) > 2 and w not in STOPWORDS}

    @staticmethod
    def _preview(text: str, max_len: int = 240) -> str:
        compact = re.sub(r"\s+", " ", (text or "")).strip()
        return compact[:max_len]

    @staticmethod
    def _signature(payload: dict) -> str:
        if not MEMORY_WRITE_SECRET:
            return ""
        data = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(f"{MEMORY_WRITE_SECRET}:{data}".encode("utf-8")).hexdigest()

    @staticmethod
    def _base_score(importance: float, created_at: str, recall_count: int) -> float:
        age_seconds = max(0.0, time.time() - MemoryManager._safe_ts(created_at))
        decay_window = max(24 * 3600, MEMORY_DECAY_DAYS * 24 * 3600)
        recency = math.exp(-age_seconds / decay_window)
        reinforcement = min(1.0, math.log1p(max(0, recall_count)) / 2.5)
        score = (float(importance) * 0.6) + (recency * 0.25) + (reinforcement * 0.15)
        return max(0.0, min(score, 1.0))

    async def remember(
        self,
        *,
        content: str,
        memory_type: str,
        source_type: str,
        session_id: Optional[str] = None,
        source_id: Optional[str] = None,
        summary: Optional[str] = None,
        metadata: Optional[dict] = None,
        importance: float = 0.5,
        confidence: float = 0.7,
        reason: str = "memory_write",
    ) -> Optional[str]:
        expires_at = None
        if importance < 0.5:
            expires_at = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        memory_id, created = await add_memory_item(
            content=content,
            memory_type=memory_type,
            source_type=source_type,
            session_id=session_id,
            source_id=source_id,
            summary=summary,
            metadata=metadata,
            importance=importance,
            confidence=confidence,
            expires_at=expires_at,
        )
        if not memory_id:
            return None
        payload = {
            "memory_id": memory_id,
            "created": created,
            "memory_type": memory_type,
            "source_type": source_type,
            "source_id": source_id,
        }
        await add_memory_audit_event(
            event_type="memory_write" if created else "memory_touch",
            actor="memory_manager",
            session_id=session_id,
            reason=reason,
            payload=payload,
            signature=self._signature(payload),
        )
        return memory_id

    def _rank_with_python(self, query_tokens: set[str], candidates: list[dict]) -> list[dict]:
        ranked: list[dict] = []
        for item in candidates:
            text = item.get("summary") or item.get("content", "")
            content_tokens = self._tokenize(text)
            lexical = 0.0
            if query_tokens and content_tokens:
                overlap = len(query_tokens & content_tokens)
                if overlap:
                    coverage = overlap / max(1, len(query_tokens))
                    precision = overlap / max(1, len(content_tokens))
                    lexical = (coverage * 0.7) + (precision * 0.3)
            base = self._base_score(
                importance=float(item.get("importance") or 0.0),
                created_at=item.get("created_at"),
                recall_count=int(item.get("recall_count") or 0),
            )
            final_score = base if not query_tokens else (base * 0.5) + (lexical * 0.5)
            if final_score >= MEMORY_MIN_SCORE or lexical >= 0.45:
                ranked.append({**item, "_score": round(final_score, 4)})
        ranked.sort(key=lambda x: x["_score"], reverse=True)
        return ranked

    async def _rank_with_accelerator(self, query: str, candidates: list[dict], limit: int) -> list[dict]:
        accelerator_results = await rank_memory_candidates(query=query, candidates=candidates, limit=limit)
        if not accelerator_results:
            return []
        by_id = {row["id"]: row for row in candidates}
        ranked = []
        for row in accelerator_results:
            item = by_id.get(row["id"])
            if not item:
                continue
            ranked.append({**item, "_score": round(float(row.get("score", 0.0)), 4)})
        ranked.sort(key=lambda x: x["_score"], reverse=True)
        return ranked

    async def _retrieve_kb_passages(self, query: str) -> list[dict]:
        q = str(query or "").strip()
        if not q:
            return []
        candidates = await search_crawl_passages_fts(query=q, limit=max(1, KB_RETRIEVAL_CANDIDATES))
        if not candidates:
            return []

        if KB_RERANK_ENABLED:
            try:
                ordering = await nim_retrieval_client.rerank(
                    query=q,
                    passages=[str(row.get("content") or "") for row in candidates],
                    model=KB_RERANK_MODEL,
                )
                candidates = [candidates[idx] for idx in ordering if 0 <= idx < len(candidates)]
            except Exception:
                pass

        return candidates[: max(1, KB_RETRIEVAL_LIMIT)]

    async def retrieve_context(self, session_id: str, query: str, limit: int = MEMORY_RETRIEVAL_LIMIT) -> dict:
        query_tokens = self._tokenize(query)
        candidates = await get_memory_candidates(session_id=session_id, limit=MEMORY_CANDIDATE_LIMIT)
        ranked = await self._rank_with_accelerator(query=query, candidates=candidates, limit=limit)
        if not ranked:
            ranked = self._rank_with_python(query_tokens=query_tokens, candidates=candidates)
        selected = ranked[:max(1, limit)]
        kb_items = await self._retrieve_kb_passages(query)
        if selected:
            await increment_memory_recall([item["id"] for item in selected])
            payload = {
                "query_hash": hashlib.sha256((query or "").encode("utf-8")).hexdigest()[:16],
                "selected_memory_ids": [item["id"] for item in selected],
                "kb_hits": len(kb_items),
            }
            await add_memory_audit_event(
                event_type="memory_injected",
                actor="memory_manager",
                session_id=session_id,
                reason="prompt_augmentation",
                payload=payload,
                signature=self._signature(payload),
            )

        context = self._format_context(selected, kb_items)
        return {"context": context, "items": selected, "kb_items": kb_items}

    def _format_context(self, items: list[dict], kb_items: list[dict]) -> str:
        if not items and not kb_items:
            return ""
        lines = ["Persistent memory to consider before answering:"]
        for idx, item in enumerate(items, start=1):
            created_at = item.get("created_at", "")[:19]
            src = f"{item.get('source_type', 'unknown')}/{item.get('memory_type', 'semantic')}"
            text = self._preview(item.get("summary") or item.get("content") or "", 280)
            lines.append(f"{idx}. [{created_at}] ({src}) {text}")
        if kb_items:
            lines.append("\nKnowledge base passages:")
            for idx, item in enumerate(kb_items, start=1):
                source = str(item.get("source_url") or "unknown")
                domain = str(item.get("domain") or "unknown")
                text = self._preview(item.get("snippet") or item.get("content") or "", 280)
                lines.append(f"{idx}. [{domain}] {source} :: {text}")
        return "\n".join(lines)

    async def _extract_facts_nim(self, user_message: str, assistant_message: str) -> list[dict]:
        if not MEMORY_ENABLE_NIM_EXTRACTION:
            return []
        prompt = f"""Extract durable long-term memory items from this interaction.
Return only strict JSON:
{{
  "facts": [
    {{"fact": "text", "memory_type": "semantic|procedural|self_model", "importance": 0.0}}
  ]
}}
Rules:
- max 6 facts
- each fact under 180 characters
- ignore small talk and transient details
- focus on reusable user intent, targets, preferences, outcomes

USER:
{user_message}

ASSISTANT:
{assistant_message}
"""
        try:
            result = await model_router.query(
                messages=[
                    {"role": "system", "content": "You produce valid JSON only."},
                    {"role": "user", "content": prompt},
                ],
                force_model=MEMORY_EXTRACTION_MODEL,
                temperature=0.1,
            )
            payload = _extract_json_object(result.get("response", ""))
            if not payload:
                return []
            facts = payload.get("facts", [])
            cleaned = []
            if isinstance(facts, list):
                for row in facts[:6]:
                    if not isinstance(row, dict):
                        continue
                    fact = str(row.get("fact", "")).strip()
                    if not fact:
                        continue
                    cleaned.append({
                        "fact": self._preview(fact, 180),
                        "memory_type": row.get("memory_type", "semantic"),
                        "importance": float(row.get("importance", 0.55)),
                    })
            return cleaned
        except Exception:
            return []

    def _extract_facts_heuristic(self, user_message: str, assistant_message: str) -> list[dict]:
        source = f"{user_message}\n{assistant_message}"
        sentences = re.split(r"(?<=[.!?])\s+|\n+", source)
        keywords = {
            "target", "host", "ip", "domain", "scan", "port", "vulnerability", "cve",
            "credential", "severity", "methodology", "owasp", "mitre", "kill chain",
            "prefer", "always", "never", "tool", "nmap", "sqlmap", "nikto",
        }
        procedural_words = {"prefer", "always", "never", "workflow", "procedure", "playbook"}
        high_value_words = {"critical", "high", "urgent", "exploit", "breach", "rce"}

        facts = []
        for sentence in sentences:
            cleaned = self._preview(sentence, 200)
            lowered = cleaned.lower()
            if len(cleaned) < 30:
                continue
            if not any(keyword in lowered for keyword in keywords):
                continue
            memory_type = "procedural" if any(word in lowered for word in procedural_words) else "semantic"
            importance = 0.7 if any(word in lowered for word in high_value_words) else 0.55
            facts.append({"fact": cleaned, "memory_type": memory_type, "importance": importance})
            if len(facts) >= 6:
                break
        return facts

    async def ingest_chat_turn(
        self,
        session_id: str,
        user_message: str,
        assistant_message: str,
        task_type: str = "chat",
        model_used: Optional[str] = None,
        durable_to_global: bool = False,
    ):
        """Persist durable memory extracted from a completed chat turn."""
        try:
            episodic_summary = (
                f"User asked: {self._preview(user_message, 180)} | "
                f"Assistant response: {self._preview(assistant_message, 220)}"
            )
            await self.remember(
                content=episodic_summary,
                summary=self._preview(episodic_summary, 180),
                memory_type="episodic",
                source_type="chat",
                session_id=session_id,
                metadata={"task_type": task_type, "model_used": model_used},
                importance=0.45,
                confidence=0.75,
                reason="chat_turn_snapshot",
            )

            extracted = await self._extract_facts_nim(user_message, assistant_message)
            if not extracted:
                extracted = self._extract_facts_heuristic(user_message, assistant_message)

            durable_session_id = None if durable_to_global else session_id
            for item in extracted:
                await self.remember(
                    content=item["fact"],
                    summary=self._preview(item["fact"], 140),
                    memory_type=item.get("memory_type", "semantic"),
                    source_type="chat",
                    session_id=durable_session_id,
                    metadata={"task_type": task_type},
                    importance=float(item.get("importance", 0.55)),
                    confidence=0.72,
                    reason="chat_fact_extraction",
                )

            await self.create_checkpoint(
                session_id=session_id,
                checkpoint_type="chat_turn",
                state={
                    "task_type": task_type,
                    "model_used": model_used,
                    "user_message": self._preview(user_message, 600),
                    "assistant_message": self._preview(assistant_message, 1200),
                    "fact_count": len(extracted),
                },
                reason="chat_turn_checkpoint",
            )
        except Exception:
            await add_memory_audit_event(
                event_type="memory_ingest_error",
                actor="memory_manager",
                session_id=session_id,
                reason="chat_turn_ingest",
                payload={"task_type": task_type},
            )

    async def ingest_scan_result(
        self,
        *,
        scan_id: str,
        target: str,
        phase: str,
        tool_name: str,
        command: str,
        output: str,
        findings: list[str],
        severity: str,
    ):
        """Persist scan artifacts as semantic and episodic memory."""
        severity_score = {
            "critical": 0.95,
            "high": 0.85,
            "medium": 0.72,
            "low": 0.58,
            "info": 0.45,
        }
        base_importance = severity_score.get((severity or "info").lower(), 0.5)
        summary = (
            f"Scan {scan_id[:8]} on {target}: {tool_name} in {phase} "
            f"reported {severity.upper()} severity."
        )
        metadata = {"target": target, "phase": phase, "tool": tool_name, "command": command}

        await self.remember(
            content=summary,
            summary=summary,
            memory_type="semantic",
            source_type="scan_result",
            session_id=None,
            source_id=scan_id,
            metadata=metadata,
            importance=base_importance,
            confidence=0.82,
            reason="scan_result_summary",
        )

        if output:
            await self.remember(
                content=self._preview(output, 1400),
                summary=f"{tool_name} output snapshot for {target}",
                memory_type="episodic",
                source_type="scan_output",
                session_id=None,
                source_id=scan_id,
                metadata=metadata,
                importance=max(0.4, base_importance - 0.1),
                confidence=0.7,
                reason="scan_output_snapshot",
            )

        for finding in (findings or [])[:3]:
            if not finding:
                continue
            await self.remember(
                content=self._preview(str(finding), 500),
                summary=f"Finding from {tool_name} on {target}",
                memory_type="semantic",
                source_type="scan_finding",
                session_id=None,
                source_id=scan_id,
                metadata=metadata,
                importance=base_importance,
                confidence=0.78,
                reason="scan_finding",
            )

    async def teach(
        self,
        *,
        session_id: Optional[str],
        content: str,
        memory_type: str = "semantic",
        importance: float = 0.8,
        metadata: Optional[dict] = None,
    ) -> Optional[str]:
        """Manual memory write API for explicit user teaching."""
        return await self.remember(
            content=content,
            summary=self._preview(content, 180),
            memory_type=memory_type,
            source_type="manual",
            session_id=session_id,
            metadata=metadata,
            importance=importance,
            confidence=0.95,
            reason="manual_teach",
        )

    async def create_checkpoint(
        self,
        *,
        session_id: str,
        checkpoint_type: str,
        state: dict,
        reason: str = "checkpoint",
    ) -> str:
        checkpoint_id = await save_memory_checkpoint(
            session_id=session_id,
            checkpoint_type=checkpoint_type,
            state=state or {},
        )
        payload = {
            "checkpoint_id": checkpoint_id,
            "checkpoint_type": checkpoint_type,
        }
        await add_memory_audit_event(
            event_type="checkpoint_create",
            actor="memory_manager",
            session_id=session_id,
            reason=reason,
            payload=payload,
            signature=self._signature(payload),
        )
        return checkpoint_id

    async def _summarize_cluster(self, items: list[dict]) -> str:
        texts = [self._preview(item.get("content", ""), 240) for item in items if item.get("content")]
        if not texts:
            return ""
        if MEMORY_ENABLE_NIM_EXTRACTION:
            prompt = (
                "Compress the following memory snippets into 3 short durable bullet points. "
                "Keep concrete facts only.\n\n- " + "\n- ".join(texts[:20])
            )
            try:
                result = await model_router.query(
                    messages=[
                        {"role": "system", "content": "You summarize facts for long-term memory."},
                        {"role": "user", "content": prompt},
                    ],
                    force_model=MEMORY_EXTRACTION_MODEL,
                    temperature=0.1,
                )
                response = self._preview(result.get("response", ""), 700)
                if response:
                    return response
            except Exception:
                pass
        # Fallback compression when LLM extraction fails.
        unique = []
        seen = set()
        for text in texts:
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(text)
            if len(unique) >= 6:
                break
        return " | ".join(unique)

    async def consolidate_session(self, session_id: str) -> dict:
        """Compress low-value historical memory entries into a summary memory."""
        items = await list_memory_items(session_id=session_id, limit=400)
        if len(items) < 8:
            return {"session_id": session_id, "compressed": 0, "deleted": 0}

        now = time.time()
        candidates = []
        seen_hashes = set()
        for item in items:
            if item.get("source_type") == "consolidation":
                continue
            created_age_days = (now - self._safe_ts(item.get("created_at"))) / 86400
            if created_age_days < 1.0:
                continue
            if int(item.get("recall_count") or 0) > 1 and float(item.get("importance") or 0) >= 0.6:
                continue
            content = (item.get("content") or "").strip()
            if not content:
                continue
            signature = hashlib.sha256(content.lower().encode("utf-8")).hexdigest()
            if signature in seen_hashes:
                continue
            seen_hashes.add(signature)
            candidates.append(item)
            if len(candidates) >= 30:
                break

        if len(candidates) < 6:
            return {"session_id": session_id, "compressed": 0, "deleted": 0}

        summary = await self._summarize_cluster(candidates)
        if not summary:
            return {"session_id": session_id, "compressed": 0, "deleted": 0}

        await self.remember(
            content=summary,
            summary=self._preview(summary, 220),
            memory_type="semantic",
            source_type="consolidation",
            session_id=session_id,
            metadata={"consolidated_count": len(candidates)},
            importance=0.65,
            confidence=0.8,
            reason="nightly_consolidation",
        )
        deleted = await delete_memory_items([item["id"] for item in candidates])
        payload = {"session_id": session_id, "compressed": len(candidates), "deleted": deleted}
        await add_memory_audit_event(
            event_type="memory_consolidate",
            actor="memory_manager",
            session_id=session_id,
            reason="maintenance_cycle",
            payload=payload,
            signature=self._signature(payload),
        )
        self._last_consolidation[session_id] = time.time()
        return payload

    async def prune_global(self, max_items: int = MEMORY_MAX_ITEMS) -> dict:
        stats = await get_memory_stats()
        total = int(stats.get("total_items", 0))
        if total <= max_items:
            return {"deleted": 0, "total_items": total}

        items = await list_memory_items(session_id=None, limit=total)
        scored = []
        for item in items:
            score = self._base_score(
                importance=float(item.get("importance") or 0),
                created_at=item.get("created_at"),
                recall_count=int(item.get("recall_count") or 0),
            )
            scored.append((score, item["id"]))
        scored.sort(key=lambda x: x[0])  # lowest score first
        to_delete = [item_id for _, item_id in scored[:max(0, total - max_items)]]
        deleted = await delete_memory_items(to_delete)

        payload = {"deleted": deleted, "before": total, "after_target": max_items}
        await add_memory_audit_event(
            event_type="memory_prune",
            actor="memory_manager",
            reason="capacity_guardrail",
            payload=payload,
            signature=self._signature(payload),
        )
        return payload

    async def maintenance_cycle(self) -> dict:
        sessions = await list_memory_sessions(limit=200)
        consolidated = 0
        deleted = 0
        now = time.time()
        for row in sessions:
            session_id = row.get("session_id")
            if not session_id:
                continue
            last = self._last_consolidation.get(session_id, 0)
            if now - last < 3600:
                continue
            result = await self.consolidate_session(session_id)
            consolidated += int(result.get("compressed", 0))
            deleted += int(result.get("deleted", 0))
        prune_result = await self.prune_global()
        deleted += int(prune_result.get("deleted", 0))
        return {"consolidated": consolidated, "deleted": deleted}

    async def _maintenance_loop(self):
        while not self._stop_event.is_set():
            try:
                await self.maintenance_cycle()
            except Exception as exc:
                await add_memory_audit_event(
                    event_type="maintenance_error",
                    actor="memory_manager",
                    reason="maintenance_loop",
                    payload={"error": str(exc)},
                )
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=max(60, MEMORY_MAINTENANCE_INTERVAL_MIN * 60),
                )
            except asyncio.TimeoutError:
                continue

    async def start(self):
        if not MEMORY_AUTO_MAINTENANCE:
            return
        if self._maintenance_task and not self._maintenance_task.done():
            return
        self._stop_event.clear()
        self._maintenance_task = asyncio.create_task(self._maintenance_loop())
        await add_memory_audit_event(
            event_type="maintenance_start",
            actor="memory_manager",
            reason="startup",
            payload={"interval_min": MEMORY_MAINTENANCE_INTERVAL_MIN},
        )

    async def stop(self):
        if not self._maintenance_task:
            return
        self._stop_event.set()
        self._maintenance_task.cancel()
        try:
            await self._maintenance_task
        except BaseException:
            pass
        finally:
            self._maintenance_task = None
        await add_memory_audit_event(
            event_type="maintenance_stop",
            actor="memory_manager",
            reason="shutdown",
            payload={},
        )


memory_manager = MemoryManager()
