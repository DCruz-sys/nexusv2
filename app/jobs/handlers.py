"""Job handler implementations."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from app.ai.memory_manager import memory_manager
from app.config import (
    ENABLE_DISTILLATION_PIPELINE,
    LEARNING_SOURCE_BATCH_SIZE,
    LEARNING_SOURCE_DISTILL_MIN_NEW_DOCS,
    MAX_PENDING_DISTILL,
)
from app.database import (
    add_learning_source_event,
    add_memory_audit_event,
    add_swarm_event,
    count_pending_jobs,
    enqueue_job,
    get_learning_source,
)
from app.ai.agent_swarm import agent_swarm
from app.engine.scanner import run_scan
from app.learning.crawler import run_crawl_cycle, run_learning_source_cycle
from app.learning.distill import run_distillation
from app.services.scan_events import broadcast_scan_event


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_payload(payload: str | dict) -> dict:
    if isinstance(payload, dict):
        return payload
    if not payload:
        return {}
    try:
        decoded = json.loads(payload)
        return decoded if isinstance(decoded, dict) else {}
    except Exception:
        return {}


async def handle_scan_job(payload: dict):
    scan_id = payload.get("scan_id")
    target = payload.get("target")
    methodology = payload.get("methodology", "owasp")
    scan_type = payload.get("scan_type", "full")
    config = payload.get("config", {}) or {}
    if not scan_id or not target:
        raise ValueError("scan payload missing scan_id/target")

    async def progress_cb(data: dict):
        await broadcast_scan_event(scan_id, data)

    await run_scan(
        scan_id=scan_id,
        target=target,
        methodology=methodology,
        scan_type=scan_type,
        config=config,
        progress_callback=progress_cb,
    )

    # Autonomous post-scan learning loop with cooldown and queue guards.
    try:
        await agent_swarm._queue_autonomous_learning(scan_id, target)
    except Exception:
        await add_memory_audit_event(
            event_type="scan_learning_enqueue_error",
            actor="job_runner",
            session_id=scan_id,
            reason="post_scan_learning",
            payload={"target": target},
        )


async def handle_swarm_job(payload: dict):
    run_id = str(payload.get("run_id") or "").strip()
    if not run_id:
        raise ValueError("swarm payload missing run_id")
    await agent_swarm.execute_persistent_run(run_id)


async def handle_crawl_job(payload: dict):
    run_id = str(payload.get("run_id") or "").strip()
    seeds = payload.get("seeds")
    metrics = await run_crawl_cycle(
        seed_urls=seeds if isinstance(seeds, list) else None,
        max_depth=payload.get("max_depth"),
        max_pages_per_day=payload.get("max_pages_per_day"),
        max_pages_per_domain=payload.get("max_pages_per_domain"),
        allow_subdomains=payload.get("allow_subdomains"),
    )
    distill_job_id = None
    if bool(payload.get("distill_after")) and ENABLE_DISTILLATION_PIPELINE:
        try:
            pending = await count_pending_jobs("distill")
            if pending < MAX_PENDING_DISTILL:
                next_run_at = (_utcnow() + timedelta(seconds=60)).isoformat()
                distill_job_id = await enqueue_job(
                    job_type="distill",
                    payload={"trigger": "after_crawl", "limit": 300, "run_id": run_id or None},
                    max_attempts=2,
                    next_run_at=next_run_at,
                )
                await add_memory_audit_event(
                    event_type="distill_queued_after_crawl",
                    actor="job_runner",
                    reason="after_crawl",
                    payload={"distill_job_id": distill_job_id, "next_run_at": next_run_at, "crawl_metrics": metrics},
                )
        except Exception as exc:
            await add_memory_audit_event(
                event_type="distill_queue_error",
                actor="job_runner",
                reason="after_crawl",
                payload={"error": str(exc), "crawl_metrics": metrics},
            )
    await add_memory_audit_event(
        event_type="crawler_job_complete",
        actor="job_runner",
        reason="job_complete",
        payload={**metrics, "distill_job_id": distill_job_id},
    )
    if run_id:
        try:
            await add_swarm_event(
                run_id,
                "crawl_completed",
                {**metrics, "distill_job_id": distill_job_id},
            )
        except Exception:
            pass


async def handle_maintenance_job(payload: dict):
    stats = await memory_manager.maintenance_cycle()
    await add_memory_audit_event(
        event_type="maintenance_job_complete",
        actor="job_runner",
        reason="job_complete",
        payload=stats,
    )


async def handle_crawl_source_job(payload: dict):
    source_id = str(payload.get("source_id") or "").strip()
    if not source_id:
        raise ValueError("crawl_source payload missing source_id")
    source = await get_learning_source(source_id)
    if not source:
        raise ValueError("learning_source_not_found")

    batch_size = int(payload.get("batch_size") or LEARNING_SOURCE_BATCH_SIZE)
    metrics = await run_learning_source_cycle(source_id=source_id, batch_size=batch_size)
    await add_memory_audit_event(
        event_type="learning_source_crawl_completed",
        actor="job_runner",
        session_id=source_id,
        reason="job_complete",
        payload=metrics,
    )

    distill_job_id = None
    if (
        ENABLE_DISTILLATION_PIPELINE
        and int(metrics.get("new_docs") or 0) >= int(LEARNING_SOURCE_DISTILL_MIN_NEW_DOCS)
    ):
        pending = await count_pending_jobs("distill")
        if pending < MAX_PENDING_DISTILL:
            distill_job_id = await enqueue_job(
                job_type="distill",
                payload={
                    "trigger": "learning_source",
                    "source_id": source_id,
                    "domain": source.get("domain"),
                    "limit": 400,
                },
                max_attempts=2,
            )
            await add_learning_source_event(
                source_id,
                "learning_source_distilled",
                {"distill_job_id": distill_job_id, "new_docs": int(metrics.get("new_docs") or 0)},
            )
    if distill_job_id:
        metrics["distill_job_id"] = distill_job_id


async def handle_distill_job(payload: dict):
    run_id = str(payload.get("run_id") or "").strip()
    limit = int(payload.get("limit", 300))
    lineage = {
        "source_id": payload.get("source_id"),
        "domain": payload.get("domain"),
        "trigger": payload.get("trigger"),
    }
    stats = await run_distillation(limit=limit, lineage=lineage)
    await add_memory_audit_event(
        event_type="distill_job_complete",
        actor="job_runner",
        reason="job_complete",
        payload=stats,
    )
    if run_id:
        try:
            await add_swarm_event(run_id, "distill_completed", stats)
        except Exception:
            pass


async def handle_extract_job(payload: dict):
    # Extraction is currently performed inline by crawler; keep no-op handler for queue completeness.
    await add_memory_audit_event(
        event_type="extract_job_complete",
        actor="job_runner",
        reason="noop_extract_stage",
        payload={"status": "noop"},
    )


async def handle_report_job(payload: dict):
    # Reserved for future async report generation pipeline.
    await add_memory_audit_event(
        event_type="report_job_complete",
        actor="job_runner",
        reason="noop_report_stage",
        payload={"status": "noop"},
    )


JOB_HANDLERS = {
    "scan": handle_scan_job,
    "swarm": handle_swarm_job,
    "crawl": handle_crawl_job,
    "crawl_source": handle_crawl_source_job,
    "maintenance": handle_maintenance_job,
    "distill": handle_distill_job,
    "extract": handle_extract_job,
    "report": handle_report_job,
}
