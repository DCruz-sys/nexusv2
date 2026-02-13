"""Target allowlist management routes."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.database import add_target_rule, delete_target_rule, list_target_rules
from app.security.allowlist import parse_target, target_matches_rule
from app.security.auth import require_operator, require_viewer

router = APIRouter(tags=["targets"])


class TargetRuleRequest(BaseModel):
    type: str = Field(default="domain")
    pattern: str = Field(min_length=1, max_length=512)
    created_by: str = Field(default="api")
    enabled: bool = True


@router.post("/targets")
async def api_add_target(req: TargetRuleRequest, _principal=Depends(require_operator)):
    rule_type = req.type.strip().lower()
    if rule_type not in {"domain", "ip", "cidr", "auto"}:
        raise HTTPException(status_code=400, detail="Unsupported rule type. Use domain|ip|cidr|auto")
    rule_id = await add_target_rule(
        rule_type=rule_type,
        pattern=req.pattern.strip(),
        created_by=req.created_by.strip() or "api",
        enabled=req.enabled,
    )
    return {"id": rule_id, "status": "created"}


@router.get("/targets")
async def api_list_targets(enabled_only: bool = False, _principal=Depends(require_viewer)):
    rules = await list_target_rules(enabled_only=enabled_only)
    return {"rules": rules}


@router.delete("/targets/{rule_id}")
async def api_delete_target(rule_id: str, _principal=Depends(require_operator)):
    deleted = await delete_target_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"id": rule_id, "status": "deleted"}


@router.get("/targets/check")
async def api_check_target(target: str, _principal=Depends(require_viewer)):
    info = parse_target(target)
    rules = await list_target_rules(enabled_only=True)
    matches = [rule for rule in rules if target_matches_rule(info, rule)]
    return {
        "target": target,
        "normalized": info.normalized,
        "allowed": bool(matches),
        "matches": matches,
    }
