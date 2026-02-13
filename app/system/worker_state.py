"""Helpers for API/worker split mode and worker liveness checks."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException

from app.config import JOB_RUNNER_MODE, WORKER_HEARTBEAT_SEC
from app.database import get_worker_heartbeat


def _age_seconds(updated_at_iso: str | None) -> int | None:
    if not updated_at_iso:
        return None
    try:
        updated = datetime.fromisoformat(str(updated_at_iso))
    except Exception:
        return None
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return max(0, int((now - updated).total_seconds()))


async def worker_status(role: str = "worker") -> dict:
    hb = await get_worker_heartbeat(role=role)
    age = _age_seconds(hb.get("updated_at") if hb else None)
    stale_after = max(60, int(WORKER_HEARTBEAT_SEC) * 3)
    ok = bool(hb) and (age is not None) and age <= stale_after
    return {
        "mode": JOB_RUNNER_MODE,
        "role": role,
        "ok": ok,
        "stale_after_sec": stale_after,
        "age_sec": age,
        "heartbeat": hb,
    }


async def require_worker_running(role: str = "worker"):
    if JOB_RUNNER_MODE != "external":
        return
    status = await worker_status(role=role)
    if status.get("ok"):
        return
    raise HTTPException(
        status_code=503,
        detail={
            "code": "worker_unavailable",
            "message": "Background worker is not running. Start nexuspentest-worker.service.",
            "details": {
                "mode": status.get("mode"),
                "role": role,
                "age_sec": status.get("age_sec"),
                "stale_after_sec": status.get("stale_after_sec"),
            },
        },
    )

