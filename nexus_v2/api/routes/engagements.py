"""Engagement + scope routes (v2)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from nexus_v2.api.auth import require_operator, require_viewer
from nexus_v2.infra.repos.engagements import create_engagement, get_engagement, list_engagements
from nexus_v2.infra.repos.scope_rules import add_scope_rule, list_scope_rules


router = APIRouter(prefix="/api/v2", tags=["engagements"])


class CreateEngagementRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)


@router.post("/engagements")
async def api_create_engagement(req: CreateEngagementRequest, _principal=Depends(require_operator)):
    return await create_engagement(req.name)


@router.get("/engagements")
async def api_list_engagements(limit: int = 50, offset: int = 0, _principal=Depends(require_viewer)):
    rows = await list_engagements(limit=limit, offset=offset)
    return {"engagements": rows}


@router.get("/engagements/{engagement_id}")
async def api_get_engagement(engagement_id: str, _principal=Depends(require_viewer)):
    row = await get_engagement(engagement_id)
    if not row:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return row


class CreateScopeRuleRequest(BaseModel):
    type: str = Field(pattern=r"^(domain|ip|cidr)$")
    pattern: str = Field(min_length=1, max_length=1024)
    enabled: bool = True


@router.post("/engagements/{engagement_id}/scope-rules")
async def api_add_scope_rule(engagement_id: str, req: CreateScopeRuleRequest, _principal=Depends(require_operator)):
    if not await get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="Engagement not found")
    return await add_scope_rule(
        engagement_id=engagement_id,
        rule_type=req.type,
        pattern=req.pattern,
        enabled=req.enabled,
    )


@router.get("/engagements/{engagement_id}/scope-rules")
async def api_list_scope_rules(
    engagement_id: str,
    enabled_only: bool = False,
    limit: int = 500,
    offset: int = 0,
    _principal=Depends(require_viewer),
):
    if not await get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="Engagement not found")
    rows = await list_scope_rules(
        engagement_id=engagement_id,
        enabled_only=enabled_only,
        limit=limit,
        offset=offset,
    )
    return {"scope_rules": rows}

