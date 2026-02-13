"""Background worker entry point for systemd deployments.

Runs job queue workers without serving HTTP traffic.
"""
from __future__ import annotations

import asyncio
import os
import signal
import socket
import uuid
from datetime import datetime, timezone

from app.ai.memory_manager import memory_manager
from app.ai.nim_client import nim_client
from app.ai.nim_retrieval_client import nim_retrieval_client
from app.config import WORKER_HEARTBEAT_SEC
from app.database import add_memory_audit_event, init_db, upsert_worker_heartbeat
from app.jobs.runner import job_runner


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _heartbeat_loop(worker_id: str, stop_event: asyncio.Event):
    host = socket.gethostname()
    pid = os.getpid()
    while not stop_event.is_set():
        try:
            await upsert_worker_heartbeat(
                worker_id=worker_id,
                role="worker",
                meta={"pid": pid, "host": host, "updated_at": _utcnow_iso()},
            )
        except Exception:
            # Heartbeat is best-effort; never take down the worker.
            pass
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=max(5, int(WORKER_HEARTBEAT_SEC)))
        except asyncio.TimeoutError:
            continue


async def main():
    await init_db()
    worker_id = f"worker-{uuid.uuid4().hex[:10]}"
    await add_memory_audit_event(
        event_type="worker_start",
        actor="worker",
        session_id=None,
        reason="startup",
        payload={"worker_id": worker_id},
    )

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            # Some environments (Windows) don't support loop signal handlers.
            pass

    await nim_client.start()
    await nim_retrieval_client.start()
    await memory_manager.start()
    await job_runner.start()

    hb_task = asyncio.create_task(_heartbeat_loop(worker_id, stop_event))
    try:
        await stop_event.wait()
    finally:
        hb_task.cancel()
        try:
            await hb_task
        except BaseException:
            pass
        await job_runner.stop()
        await memory_manager.stop()
        await nim_retrieval_client.stop()
        await nim_client.stop()
        await add_memory_audit_event(
            event_type="worker_stop",
            actor="worker",
            session_id=None,
            reason="shutdown",
            payload={"worker_id": worker_id},
        )


if __name__ == "__main__":
    asyncio.run(main())

