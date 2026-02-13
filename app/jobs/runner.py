"""Async job-runner for scan/crawl/maintenance/distillation queue."""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone

from app.config import (
    ANALYSIS_WORKERS,
    CRAWLER_WORKERS,
    ENABLE_AUTONOMOUS_EXECUTION,
    ENABLE_CRAWLER,
    ENABLE_DISTILLATION_PIPELINE,
    LEARNING_SOURCE_AUTONOMOUS_ENABLED,
    LEARNING_SOURCE_BATCH_SIZE,
    JOB_HEARTBEAT_SECONDS,
    MAX_PENDING_CRAWL,
    MAX_PENDING_DISTILL,
    MAX_PENDING_MAINTENANCE,
    SCAN_WORKERS,
    SCHEDULE_CRAWL_INTERVAL_HOURS,
    SCHEDULE_DISTILL_INTERVAL_HOURS,
    SCHEDULE_MAINTENANCE_INTERVAL_HOURS,
)
from app.database import (
    add_memory_audit_event,
    claim_jobs,
    complete_job,
    count_pending_jobs,
    count_learning_frontier,
    count_learning_sources,
    count_running_jobs_by_type,
    enqueue_job,
    fail_job,
    get_queue_stats,
    heartbeat_job,
    list_due_learning_sources,
    list_jobs,
    reclaim_stale_running_jobs,
    update_learning_source,
    upsert_learning_frontier_url,
)
from app.jobs.handlers import JOB_HANDLERS, parse_payload


class JobRunner:
    def __init__(self):
        self._stop_event = asyncio.Event()
        self._tasks: list[asyncio.Task] = []
        self.started_at: float | None = None
        self.last_scheduler_tick: float | None = None
        self.job_latencies_ms: list[float] = []
        self._last_schedule_at: dict[str, float] = {}

    async def _ensure_queued(self, job_type: str, max_pending: int, payload: dict, max_attempts: int = 3):
        pending = await count_pending_jobs(job_type)
        if pending >= max_pending:
            return None
        return await enqueue_job(job_type=job_type, payload=payload, max_attempts=max_attempts)

    def _should_schedule(self, job_type: str, interval_hours: int) -> bool:
        interval_seconds = max(1, interval_hours) * 3600
        now = time.time()
        last = self._last_schedule_at.get(job_type, 0.0)
        if now - last < interval_seconds:
            return False
        self._last_schedule_at[job_type] = now
        return True

    async def _scheduler_loop(self):
        while not self._stop_event.is_set():
            self.last_scheduler_tick = time.time()

            # Recover jobs orphaned by worker crashes.
            reclaimed = await reclaim_stale_running_jobs()
            if reclaimed:
                await add_memory_audit_event(
                    event_type="job_reclaimed",
                    actor="job_runner",
                    reason="stale_lease_recovery",
                    payload={"count": reclaimed},
                )

            # periodic crawl
            if ENABLE_CRAWLER and self._should_schedule("crawl", SCHEDULE_CRAWL_INTERVAL_HOURS):
                await self._ensure_queued("crawl", MAX_PENDING_CRAWL, {"scheduled": True}, max_attempts=2)

            # periodic maintenance
            if self._should_schedule("maintenance", SCHEDULE_MAINTENANCE_INTERVAL_HOURS):
                await self._ensure_queued("maintenance", MAX_PENDING_MAINTENANCE, {"scheduled": True}, max_attempts=2)

            # periodic distillation
            if ENABLE_DISTILLATION_PIPELINE and self._should_schedule("distill", SCHEDULE_DISTILL_INTERVAL_HOURS):
                await self._ensure_queued("distill", MAX_PENDING_DISTILL, {"scheduled": True, "limit": 350}, max_attempts=2)

            # persistent autonomous learning sources
            if LEARNING_SOURCE_AUTONOMOUS_ENABLED:
                await self._schedule_learning_sources()

            await asyncio.sleep(60)

    async def _schedule_learning_sources(self):
        total_sources = await count_learning_sources(enabled_only=True)
        if total_sources <= 0:
            return
        pending = await count_pending_jobs("crawl_source")
        running = await count_running_jobs_by_type("crawl_source")
        budget = max(0, max(1, MAX_PENDING_CRAWL) - pending - running)
        if budget <= 0:
            return
        due_sources = await list_due_learning_sources(limit=budget)
        if not due_sources:
            return
        for source in due_sources:
            source_id = str(source.get("id") or "")
            if not source_id:
                continue
            frontier_queued = await count_learning_frontier(source_id, status="queued")
            if frontier_queued <= 0:
                seed_url = str(source.get("seed_url") or "").strip()
                domain = str(source.get("domain") or "").strip().lower()
                if seed_url and domain:
                    await upsert_learning_frontier_url(
                        source_id=source_id,
                        url=seed_url,
                        domain=domain,
                        depth=0,
                        priority=100,
                        discovered_from=seed_url,
                    )
                frontier_queued = await count_learning_frontier(source_id, status="queued")
                if frontier_queued <= 0:
                    continue
            await enqueue_job(
                job_type="crawl_source",
                payload={"source_id": source_id, "trigger": "scheduler", "batch_size": LEARNING_SOURCE_BATCH_SIZE},
                max_attempts=2,
            )
            # Push next_run_at forward to avoid duplicate scheduling races in the same tick.
            next_run = (datetime.now(timezone.utc) + timedelta(seconds=90)).isoformat()
            await update_learning_source(
                source_id,
                next_run_at=next_run,
            )

    async def _heartbeat_loop(self, job_id: str, worker_id: str):
        while not self._stop_event.is_set():
            await heartbeat_job(job_id=job_id, worker_id=worker_id)
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=max(5, JOB_HEARTBEAT_SECONDS))
            except asyncio.TimeoutError:
                continue

    async def _worker_loop(self, job_type: str, worker_id: str):
        handler = JOB_HANDLERS.get(job_type)
        if not handler:
            return
        while not self._stop_event.is_set():
            jobs = await claim_jobs(job_type, limit=1, worker_id=worker_id)
            if not jobs:
                await asyncio.sleep(0.8)
                continue
            for job in jobs:
                job_id = job["id"]
                payload = parse_payload(job.get("payload"))
                start = time.perf_counter()
                heartbeat_task = asyncio.create_task(self._heartbeat_loop(job_id=job_id, worker_id=worker_id))
                try:
                    if job_type == "scan" and not ENABLE_AUTONOMOUS_EXECUTION:
                        raise RuntimeError("autonomous execution is disabled by feature flag")
                    await handler(payload)
                    await complete_job(job_id)
                    await add_memory_audit_event(
                        event_type="job_complete",
                        actor="job_runner",
                        reason=f"{job_type}_worker",
                        payload={"job_id": job_id, "type": job_type},
                    )
                except Exception as exc:
                    attempt = int(job.get("attempt") or 0)
                    retry_delay = min(120, 2 ** max(1, attempt))
                    await fail_job(job_id, str(exc), retry_delay_sec=retry_delay)
                    await add_memory_audit_event(
                        event_type="job_failed",
                        actor="job_runner",
                        reason=f"{job_type}_worker",
                        payload={"job_id": job_id, "type": job_type, "error": str(exc)},
                    )
                finally:
                    heartbeat_task.cancel()
                    try:
                        await heartbeat_task
                    except BaseException:
                        pass
                    elapsed_ms = (time.perf_counter() - start) * 1000.0
                    self.job_latencies_ms.append(elapsed_ms)
                    if len(self.job_latencies_ms) > 2000:
                        self.job_latencies_ms = self.job_latencies_ms[-1000:]

    async def start(self):
        if self._tasks:
            return
        self.started_at = time.time()
        self._last_schedule_at = {}
        self._stop_event.clear()
        await reclaim_stale_running_jobs()
        self._tasks.append(asyncio.create_task(self._scheduler_loop()))

        for idx in range(max(1, SCAN_WORKERS)):
            self._tasks.append(asyncio.create_task(self._worker_loop("scan", worker_id=f"scan-{idx}")))
        self._tasks.append(asyncio.create_task(self._worker_loop("swarm", worker_id="swarm-0")))
        for idx in range(max(1, CRAWLER_WORKERS)):
            self._tasks.append(asyncio.create_task(self._worker_loop("crawl", worker_id=f"crawl-{idx}")))
        self._tasks.append(asyncio.create_task(self._worker_loop("crawl_source", worker_id="crawl-source-0")))
        for idx in range(max(1, ANALYSIS_WORKERS)):
            self._tasks.append(asyncio.create_task(self._worker_loop("extract", worker_id=f"extract-{idx}")))
            self._tasks.append(asyncio.create_task(self._worker_loop("distill", worker_id=f"distill-{idx}")))
        self._tasks.append(asyncio.create_task(self._worker_loop("maintenance", worker_id="maintenance-0")))
        self._tasks.append(asyncio.create_task(self._worker_loop("report", worker_id="report-0")))

        await add_memory_audit_event(
            event_type="job_runner_start",
            actor="job_runner",
            reason="startup",
            payload={
                "scan_workers": SCAN_WORKERS,
                "swarm_workers": 1,
                "crawler_workers": CRAWLER_WORKERS,
                "analysis_workers": ANALYSIS_WORKERS,
            },
        )

    async def stop(self):
        if not self._tasks:
            return
        self._stop_event.set()
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except BaseException:
                pass
        self._tasks = []
        await add_memory_audit_event(
            event_type="job_runner_stop",
            actor="job_runner",
            reason="shutdown",
            payload={},
        )

    async def status(self):
        queue = await get_queue_stats()
        recent_jobs = await list_jobs(limit=20)
        if self.job_latencies_ms:
            sorted_lat = sorted(self.job_latencies_ms)
            p95 = sorted_lat[int(0.95 * (len(sorted_lat) - 1))]
            avg = sum(sorted_lat) / len(sorted_lat)
        else:
            p95 = 0.0
            avg = 0.0
        return {
            "running": bool(self._tasks),
            "started_at": self.started_at,
            "last_scheduler_tick": self.last_scheduler_tick,
            "queue": queue,
            "recent_jobs": recent_jobs,
            "latency_ms": {"avg": round(avg, 2), "p95": round(p95, 2)},
        }


job_runner = JobRunner()
