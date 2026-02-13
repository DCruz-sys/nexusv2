"""Scan management API routes with WebSocket progress streaming."""
from __future__ import annotations

import asyncio
import json
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from app.config import MAX_PENDING_SCANS
from app.database import (
    cancel_all_scan_jobs,
    cancel_jobs_for_scan,
    count_pending_jobs,
    create_scan,
    enqueue_job,
    get_scan,
    get_scan_results,
    list_scan_jobs,
    list_scans,
    update_scan,
)
from app.engine.scanner import get_active_scan_status
from app.security.allowlist import TargetNotAllowedError, require_target_allowed
from app.security.auth import authenticate_websocket, require_operator, require_viewer
from app.services.scan_events import broadcast_scan_event, register_scan_ws, unregister_scan_ws

router = APIRouter(tags=["scans"])


def _normalize_methodology(value: str) -> str:
    lowered = (value or "").strip().lower()
    if lowered in {"owasp", "ai", "mitre", "killchain"}:
        return lowered
    return "owasp"


def _normalize_scan_type(value: str) -> str:
    lowered = (value or "").strip().lower()
    return "quick" if lowered == "quick" else "full"


def _extract_swarm_run_id(config: dict | str | None) -> str | None:
    if isinstance(config, dict):
        value = config.get("swarm_run_id")
        return str(value) if value else None
    if isinstance(config, str):
        try:
            parsed = json.loads(config)
        except Exception:
            return None
        if isinstance(parsed, dict):
            value = parsed.get("swarm_run_id")
            return str(value) if value else None
    return None


class ScanRequest(BaseModel):
    target: str
    methodology: str = "owasp"
    scan_type: str = "full"
    config: Optional[dict] = None


@router.post("/scans")
async def create_new_scan(req: ScanRequest, _principal=Depends(require_operator)):
    """Create and queue a new scan."""
    methodology = _normalize_methodology(req.methodology)
    scan_type = _normalize_scan_type(req.scan_type)

    try:
        await require_target_allowed(req.target, actor="api", reason="scan_create")
    except TargetNotAllowedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    pending = await count_pending_jobs("scan")
    if pending >= MAX_PENDING_SCANS:
        raise HTTPException(
            status_code=429,
            detail=f"Scan queue is full ({pending}/{MAX_PENDING_SCANS}). Try again later.",
        )

    scan_id = str(uuid.uuid4())
    config = req.config or {}
    await create_scan(scan_id, req.target, scan_type, methodology, config)
    await update_scan(scan_id, status="queued", progress=0)
    job_id = await enqueue_job(
        job_type="scan",
        payload={
            "scan_id": scan_id,
            "target": req.target,
            "methodology": methodology,
            "scan_type": scan_type,
            "config": config,
        },
        max_attempts=2,
    )
    await broadcast_scan_event(scan_id, {"type": "queued", "scan_id": scan_id, "job_id": job_id, "progress": 0})
    return {
        "scan_id": scan_id,
        "job_id": job_id,
        "status": "queued",
        "target": req.target,
        "methodology": methodology,
        "scan_type": scan_type,
    }


@router.get("/scans")
async def api_list_scans(limit: int = 50, offset: int = 0, _principal=Depends(require_viewer)):
    """List scans."""
    rows = await list_scans(limit=max(1, min(limit, 500)), offset=max(0, offset))
    for row in rows:
        row["swarm_run_id"] = _extract_swarm_run_id(row.get("config"))
    return {"scans": rows}


@router.get("/scans/{scan_id}")
async def api_get_scan(scan_id: str, _principal=Depends(require_viewer)):
    """Get scan details."""
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    results = await get_scan_results(scan_id)
    active_status = get_active_scan_status(scan_id)
    jobs = await list_scan_jobs(scan_id, limit=20)
    return {
        **scan,
        "swarm_run_id": _extract_swarm_run_id(scan.get("config")),
        "results": results,
        "active_status": active_status,
        "jobs": jobs,
    }


@router.get("/scans/{scan_id}/results")
async def api_get_scan_results(scan_id: str, _principal=Depends(require_viewer)):
    """Get scan results."""
    results = await get_scan_results(scan_id)
    return {"scan_id": scan_id, "results": results}


@router.websocket("/ws/scan/{scan_id}")
async def scan_progress_websocket(websocket: WebSocket, scan_id: str):
    """WebSocket for receiving live scan progress updates."""
    _principal = await authenticate_websocket(websocket, required_role="viewer")
    if not _principal:
        return
    await websocket.accept()
    register_scan_ws(scan_id, websocket)
    try:
        scan = await get_scan(scan_id)
        if scan:
            await websocket.send_json({"type": "status", "scan": scan})
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
            except WebSocketDisconnect:
                break
    except Exception:
        pass
    finally:
        unregister_scan_ws(scan_id, websocket)


@router.post("/scans/{scan_id}/stop")
async def api_stop_scan(scan_id: str, _principal=Depends(require_operator)):
    """Stop queued/running scan and cancel queued jobs."""
    from app.engine.scanner import stop_scan

    await cancel_jobs_for_scan(scan_id)
    await stop_scan(scan_id)
    row = await get_scan(scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row.get("status") in {"queued", "pending"}:
        await update_scan(scan_id, status="stopped")
        await broadcast_scan_event(scan_id, {"type": "stopped", "scan_id": scan_id, "message": "Queued scan cancelled"})
        return {"scan_id": scan_id, "status": "stopped"}
    await update_scan(scan_id, status="stopping")
    await broadcast_scan_event(scan_id, {"type": "stopping", "scan_id": scan_id})
    return {"scan_id": scan_id, "status": "stopping"}


@router.post("/scans/stop-all")
async def api_stop_all_scans(_principal=Depends(require_operator)):
    """Stop all active scans."""
    from app.engine.scanner import stop_all_scans

    await cancel_all_scan_jobs()
    await stop_all_scans()
    return {"status": "all_stopping"}
