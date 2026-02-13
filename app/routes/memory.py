"""Persistent memory management API routes."""
import json
from typing import Optional
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.ai.memory_manager import memory_manager
from app.config import MEMORY_RANKER_BIN, SWARM_PLANNER_BIN
from app.database import (
    get_memory_audit_events,
    get_memory_checkpoint,
    get_memory_checkpoints,
    get_memory_stats,
    list_tool_capabilities,
    list_memory_items,
    verify_memory_audit_chain,
)
from app.security.auth import require_admin, require_operator, require_viewer

router = APIRouter(tags=["memory"])


def _parse_json_field(value: Optional[str]):
    if not value:
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else value
    except Exception:
        return value


class TeachMemoryRequest(BaseModel):
    content: str = Field(min_length=3, max_length=4000)
    memory_type: str = Field(default="semantic")
    importance: float = Field(default=0.8, ge=0.0, le=1.0)
    metadata: Optional[dict] = None


class CheckpointRequest(BaseModel):
    checkpoint_type: str = Field(default="manual")
    reason: str = Field(default="manual_checkpoint")
    state: dict = Field(default_factory=dict)


@router.get("/memory/session/{session_id}")
async def api_session_memory(session_id: str, limit: int = 100, offset: int = 0, _principal=Depends(require_viewer)):
    """List persisted memory for a specific session."""
    rows = await list_memory_items(
        session_id=session_id,
        limit=max(1, min(limit, 500)),
        offset=max(0, offset),
    )
    for row in rows:
        row["metadata"] = _parse_json_field(row.get("metadata"))
    return {"session_id": session_id, "items": rows}


@router.get("/memory/search")
async def api_memory_search(session_id: str, q: str, limit: int = 8, _principal=Depends(require_viewer)):
    """Retrieve top relevant memories for a query."""
    bundle = await memory_manager.retrieve_context(
        session_id=session_id,
        query=q,
        limit=max(1, min(limit, 20)),
    )
    items = bundle.get("items", [])
    for item in items:
        item["metadata"] = _parse_json_field(item.get("metadata"))
    return {
        "session_id": session_id,
        "query": q,
        "context": bundle.get("context", ""),
        "items": items,
    }


@router.post("/memory/teach/{session_id}")
async def api_teach_memory(session_id: str, req: TeachMemoryRequest, _principal=Depends(require_operator)):
    """Explicitly persist user-provided memory."""
    memory_id = await memory_manager.teach(
        session_id=session_id,
        content=req.content,
        memory_type=req.memory_type,
        importance=req.importance,
        metadata=req.metadata,
    )
    return {"session_id": session_id, "memory_id": memory_id}


@router.post("/memory/checkpoint/{session_id}")
async def api_create_checkpoint(session_id: str, req: CheckpointRequest, _principal=Depends(require_operator)):
    """Create a durable checkpoint for deterministic replay."""
    checkpoint_id = await memory_manager.create_checkpoint(
        session_id=session_id,
        checkpoint_type=req.checkpoint_type,
        state=req.state,
        reason=req.reason,
    )
    return {"session_id": session_id, "checkpoint_id": checkpoint_id}


@router.get("/memory/checkpoints/{session_id}")
async def api_list_checkpoints(session_id: str, limit: int = 50, _principal=Depends(require_viewer)):
    """List saved checkpoints for a session."""
    rows = await get_memory_checkpoints(session_id=session_id, limit=max(1, min(limit, 200)))
    for row in rows:
        try:
            row["state"] = json.loads(row.get("state_json", "{}"))
        except Exception:
            row["state"] = row.get("state_json", {})
        row.pop("state_json", None)
    return {"session_id": session_id, "checkpoints": rows}


@router.get("/memory/checkpoint/{checkpoint_id}")
async def api_get_checkpoint(checkpoint_id: str, _principal=Depends(require_viewer)):
    """Fetch a single checkpoint payload."""
    row = await get_memory_checkpoint(checkpoint_id)
    if not row:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Checkpoint not found", "details": {}})
    try:
        row["state"] = json.loads(row.get("state_json", "{}"))
    except Exception:
        row["state"] = row.get("state_json", {})
    row.pop("state_json", None)
    return row


@router.post("/memory/consolidate/{session_id}")
async def api_consolidate_session_memory(session_id: str, _principal=Depends(require_operator)):
    """Run consolidation now for one session."""
    result = await memory_manager.consolidate_session(session_id)
    return {"session_id": session_id, **result}


@router.post("/memory/maintenance/run")
async def api_run_memory_maintenance(_principal=Depends(require_operator)):
    """Run one global maintenance cycle now."""
    result = await memory_manager.maintenance_cycle()
    return result


@router.get("/memory/audit")
async def api_memory_audit(limit: int = 200, offset: int = 0, _principal=Depends(require_admin)):
    """Inspect append-only memory audit log."""
    rows = await get_memory_audit_events(limit=max(1, min(limit, 1000)), offset=max(0, offset))
    for row in rows:
        row["payload"] = _parse_json_field(row.get("payload"))
    return {"events": rows}


@router.get("/memory/audit/verify")
async def api_memory_audit_verify(limit: int = 5000, _principal=Depends(require_admin)):
    """Verify integrity of the audit hash chain."""
    result = await verify_memory_audit_chain(limit=max(1, min(limit, 200000)))
    return result


@router.get("/memory/stats")
async def api_memory_stats(session_id: Optional[str] = None, _principal=Depends(require_viewer)):
    """Get memory utilization and distribution stats."""
    stats = await get_memory_stats(session_id=session_id)
    return {"session_id": session_id, **stats}


@router.get("/memory/accelerators")
async def api_memory_accelerators(_principal=Depends(require_viewer)):
    """Report native accelerator availability."""
    ranker = Path(MEMORY_RANKER_BIN)
    planner = Path(SWARM_PLANNER_BIN)
    ranker_exists = ranker.exists() or Path(str(ranker) + ".exe").exists()
    planner_exists = planner.exists() or Path(str(planner) + ".exe").exists()
    capabilities = await list_tool_capabilities(limit=1000)
    cap_map = {row.get("tool_name"): row for row in capabilities}
    return {
        "memory_ranker": {
            "path": MEMORY_RANKER_BIN,
            "available": ranker_exists,
            "db_status": cap_map.get("memory_ranker"),
        },
        "swarm_planner": {
            "path": SWARM_PLANNER_BIN,
            "available": planner_exists,
            "db_status": cap_map.get("swarm_planner"),
        },
    }
