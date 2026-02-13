"""Persistent swarm orchestration API routes."""
from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from app.ai.agent_swarm import agent_swarm
from app.database import cancel_swarm_jobs_for_run, get_swarm_run, list_swarm_runs
from app.security.allowlist import TargetNotAllowedError
from app.security.auth import authenticate_websocket, require_operator, require_viewer
from app.services.swarm_events import register_swarm_ws, unregister_swarm_ws

router = APIRouter(tags=["swarm"])


class SwarmRunRequest(BaseModel):
    target: str = Field(min_length=1, max_length=1024)
    objective: str = Field(min_length=3, max_length=4000)
    methodology: str = Field(default="owasp")
    scan_type: str = Field(default="quick")
    config: Optional[dict] = None


@router.post("/api/swarm/runs")
async def api_create_swarm_run(req: SwarmRunRequest, _principal=Depends(require_operator)):
    try:
        run_id, job_id = await agent_swarm.queue_swarm_run(
            target=req.target.strip(),
            objective=req.objective.strip(),
            methodology=(req.methodology or "owasp").strip().lower(),
            scan_type="full" if (req.scan_type or "").strip().lower() == "full" else "quick",
            config=req.config or {},
        )
    except TargetNotAllowedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    run = await get_swarm_run(run_id)
    return {
        "run_id": run_id,
        "job_id": job_id,
        "status": "queued",
        "created_at": run.get("created_at") if run else None,
    }


@router.get("/api/swarm/runs")
async def api_list_swarm_runs(
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
    _principal=Depends(require_viewer),
):
    rows = await list_swarm_runs(limit=max(1, min(limit, 500)), offset=max(0, offset), status=status)
    return {"runs": rows}


@router.get("/api/swarm/runs/{run_id}")
async def api_get_swarm_run(run_id: str, _principal=Depends(require_viewer)):
    bundle = await agent_swarm.get_run_bundle(run_id)
    if not bundle.get("run"):
        raise HTTPException(status_code=404, detail="Swarm run not found")
    return bundle


@router.post("/api/swarm/runs/{run_id}/stop")
async def api_stop_swarm_run(run_id: str, _principal=Depends(require_operator)):
    run = await get_swarm_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Swarm run not found")
    await cancel_swarm_jobs_for_run(run_id)
    await agent_swarm.stop_persistent_run(run_id)
    return {"run_id": run_id, "status": "stopping"}


@router.websocket("/ws/swarm/{run_id}")
async def swarm_progress_websocket(websocket: WebSocket, run_id: str):
    principal = await authenticate_websocket(websocket, required_role="viewer")
    if not principal:
        return
    await websocket.accept()
    register_swarm_ws(run_id, websocket)
    try:
        current = await agent_swarm.get_run_bundle(run_id)
        await websocket.send_json({"type": "status", "run": current.get("run"), "tasks": current.get("tasks", [])})
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
        unregister_swarm_ws(run_id, websocket)
