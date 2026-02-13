"""System diagnostics (v2)."""

from __future__ import annotations

import os
import platform
import time

from fastapi import APIRouter, Depends

from nexus_v2.api.auth import require_viewer
from nexus_v2.config import get_settings
from nexus_v2.infra.db.sqlite import get_db
from nexus_v2.infra.repos.workers import get_latest_worker_heartbeat
from nexus_v2.infra.tools.registry_yaml import tool_registry


router = APIRouter(prefix="/api/v2/system", tags=["system"])


@router.get("/readiness")
async def api_readiness(_principal=Depends(require_viewer)):
    settings = get_settings()
    checks = {
        "database": {"ok": False},
        "auth": {"ok": not settings.auth_enabled or settings.auth_jwt_secret not in {"", "change-me-in-production"}},
        "tool_catalog": {"ok": False, "count": 0},
        "platform": {"ok": True, "value": platform.platform()},
    }

    try:
        db = await get_db()
        try:
            cur = await db.execute("SELECT 1 AS ok")
            row = await cur.fetchone()
            checks["database"]["ok"] = bool(row and int(row["ok"]) == 1)
        finally:
            await db.close()
    except Exception as exc:
        checks["database"]["error"] = str(exc)

    try:
        checks["tool_catalog"]["count"] = len(tool_registry.list())
        checks["tool_catalog"]["ok"] = checks["tool_catalog"]["count"] > 0
    except Exception as exc:
        checks["tool_catalog"]["error"] = str(exc)

    return {"timestamp": int(time.time()), "checks": checks}


@router.get("/worker")
async def api_worker(_principal=Depends(require_viewer)):
    hb = await get_latest_worker_heartbeat(role="worker")
    return {"heartbeat": hb}


@router.get("/tools")
async def api_tools(_principal=Depends(require_viewer)):
    tools = [r.__dict__ for r in tool_registry.list()]
    return {"tools": tools}

