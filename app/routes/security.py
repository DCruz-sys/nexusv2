"""Security policy management routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.database import get_command_policy, list_command_policies, upsert_command_policy
from app.security.auth import require_admin, require_viewer

router = APIRouter(tags=["security"])


class CommandPolicyRequest(BaseModel):
    tool: str = Field(min_length=1, max_length=128)
    allowed_args: list[str] = Field(default_factory=list)
    blocked_args: list[str] = Field(default_factory=list)
    hitl_required: bool = False


@router.get("/security/command-policy")
async def api_get_command_policy(tool: str | None = None, limit: int = 500, _principal=Depends(require_viewer)):
    if tool:
        row = await get_command_policy(tool)
        return {"tool": tool, "policy": row}
    rows = await list_command_policies(limit=max(1, min(limit, 5000)))
    return {"policies": rows}


@router.put("/security/command-policy")
async def api_put_command_policy(req: CommandPolicyRequest, _principal=Depends(require_admin)):
    await upsert_command_policy(
        tool_name=req.tool.strip().lower(),
        allowed_args=req.allowed_args,
        blocked_args=req.blocked_args,
        hitl_required=req.hitl_required,
    )
    return {"status": "updated", "tool": req.tool.strip().lower()}
