"""Minimal MCP-like endpoint (v2).

This is not a full MCP server implementation; it's a safe, internal-only tool
gateway inspired by MCP usage in other agents. It intentionally does not expose
arbitrary command execution.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from nexus_v2.api.auth import require_operator, require_viewer
from nexus_v2.infra.repos.events import list_events
from nexus_v2.infra.repos.findings import list_findings
from nexus_v2.infra.repos.runs import get_run


router = APIRouter(prefix="/mcp/v2", tags=["mcp"])


@router.get("")
async def mcp_manifest(_principal=Depends(require_viewer)):
    return {
        "name": "nexus-v2",
        "version": "0.1",
        "tools": [
            {"name": "get_run", "args_schema": {"run_id": "string"}},
            {"name": "list_run_events", "args_schema": {"run_id": "string", "since_seq": "int"}},
            {"name": "list_findings", "args_schema": {"run_id": "string"}},
        ],
    }


class MCPCall(BaseModel):
    tool: str = Field(min_length=1, max_length=64)
    args: dict = Field(default_factory=dict)


@router.post("/call")
async def mcp_call(req: MCPCall, _principal=Depends(require_operator)):
    tool = req.tool.strip()
    args = req.args or {}
    if tool == "get_run":
        run_id = str(args.get("run_id") or "")
        run = await get_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        return {"run": run}
    if tool == "list_run_events":
        run_id = str(args.get("run_id") or "")
        since_seq = int(args.get("since_seq") or 0)
        return {"events": await list_events(run_id=run_id, since_seq=since_seq, limit=500)}
    if tool == "list_findings":
        run_id = str(args.get("run_id") or "")
        return {"findings": await list_findings(run_id=run_id, limit=500)}
    raise HTTPException(status_code=400, detail="Unknown tool")

