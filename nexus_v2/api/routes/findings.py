"""Finding routes (v2)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from nexus_v2.api.auth import require_operator, require_viewer
from nexus_v2.infra.repos.events import append_event
from nexus_v2.infra.repos.findings import get_finding, list_findings, update_finding, list_evidence
from nexus_v2.infra.repos.runs import get_run
from nexus_v2.infra.repos.tasks import insert_tasks


router = APIRouter(prefix="/api/v2", tags=["findings"])


@router.get("/runs/{run_id}/findings")
async def api_list_findings(run_id: str, limit: int = 500, _principal=Depends(require_viewer)):
    run = await get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    rows = await list_findings(run_id=run_id, limit=limit)
    return {"run_id": run_id, "findings": rows}


@router.get("/findings/{finding_id}")
async def api_get_finding(finding_id: str, _principal=Depends(require_viewer)):
    finding = await get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    evidence = await list_evidence(finding_id=finding_id, limit=200)
    return {"finding": finding, "evidence": evidence}


class ValidateFindingRequest(BaseModel):
    # For now we keep it simple: validation creates a curl task + judge task.
    kind: str = Field(default="http_exchange")


@router.post("/findings/{finding_id}/validate")
async def api_validate_finding(finding_id: str, req: ValidateFindingRequest, _principal=Depends(require_operator)):
    finding = await get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    run_id = str(finding.get("run_id") or "")
    run = await get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if str(run.get("status") or "") in {"stopping", "stopped"}:
        raise HTTPException(status_code=409, detail="Run is stopping/stopped")

    short = finding_id.replace("find_", "")[:8]
    nonce = uuid.uuid4().hex[:4]
    tool_task_id = f"validate_{short}_curl_{nonce}"
    judge_task_id = f"judge_{short}_{nonce}"

    # Mark finding as awaiting validation.
    if str(finding.get("state") or "") in {"hypothesis", "needs_validation"}:
        await update_finding(finding_id=finding_id, state="needs_validation")

    tasks = [
        {
            "task_id": tool_task_id,
            "type": "tool",
            "objective": f"Validation HTTP exchange for finding {finding_id}",
            "dependencies": [],
            "priority": 50,
            "risk_level": "low",
            "timeout_sec": 60,
            "retry_policy": {"max_attempts": 0, "backoff_sec": 0},
            "hitl_required": False,
            "tool": {"name": "curl", "params": {"args": "-iL"}},
            "output_contract": {"format": "text", "fields": []},
        },
        {
            "task_id": judge_task_id,
            "type": "control",
            "objective": f"Judge validation evidence for finding {finding_id}",
            "dependencies": [tool_task_id],
            "priority": 40,
            "risk_level": "low",
            "timeout_sec": 30,
            "retry_policy": {"max_attempts": 0, "backoff_sec": 0},
            "hitl_required": False,
            "control": {
                "action": "validation_judge",
                "params": {"finding_id": finding_id, "source_task_id": tool_task_id},
            },
            "output_contract": {"format": "json", "fields": ["state"]},
        },
    ]
    await insert_tasks(run_id=run_id, task_specs=tasks)
    await append_event(run_id=run_id, event_type="validation_queued", payload={"finding_id": finding_id, "tasks": [tool_task_id, judge_task_id]})
    return {"finding_id": finding_id, "run_id": run_id, "queued_tasks": [tool_task_id, judge_task_id]}
