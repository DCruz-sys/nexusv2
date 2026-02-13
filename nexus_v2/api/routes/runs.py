"""Run routes (v2)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from jsonschema import validate as jsonschema_validate

from nexus_v2.api.auth import require_operator, require_viewer
from nexus_v2.config import get_settings
from nexus_v2.core.usecases.scope import TargetNotAllowedError, require_target_allowed
from nexus_v2.infra.repos.engagements import get_engagement
from nexus_v2.infra.repos.events import append_event, list_events
from nexus_v2.infra.repos.runs import create_run, get_run, list_runs, mark_run_stopping
from nexus_v2.infra.repos.scope_rules import list_scope_rules
from nexus_v2.infra.repos.tasks import cancel_queued_tasks_for_run, create_task_graph, insert_tasks, list_tasks


router = APIRouter(prefix="/api/v2", tags=["runs"])


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_task_graph_schema() -> dict:
    settings = get_settings()
    path = Path(settings.schemas_dir) / "run_task_graph.schema.json"
    if not path.exists():
        raise RuntimeError(f"schema_missing:{path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize_scan_mode(value: str | None) -> str:
    v = (value or "quick").strip().lower()
    if v not in {"ci", "quick", "standard", "deep"}:
        return "quick"
    return v


class CreateRunRequest(BaseModel):
    kind: str = Field(default="scan")
    target: str = Field(min_length=1, max_length=2048)
    scan_mode: str = Field(default="quick")


@router.post("/engagements/{engagement_id}/runs")
async def api_create_run(engagement_id: str, req: CreateRunRequest, _principal=Depends(require_operator)):
    engagement = await get_engagement(engagement_id)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")

    rules = await list_scope_rules(engagement_id=engagement_id, enabled_only=True, limit=2000, offset=0)
    try:
        require_target_allowed(req.target, rules)
    except TargetNotAllowedError as exc:
        raise HTTPException(status_code=403, detail=f"Target outside allowed scope ({exc}).") from exc

    kind = (req.kind or "scan").strip().lower()
    if kind not in {"scan"}:
        raise HTTPException(status_code=400, detail="Only kind=scan is implemented in v2 right now.")

    scan_mode = _normalize_scan_mode(req.scan_mode)
    run = await create_run(
        engagement_id=engagement_id,
        kind=kind,
        target={"target": req.target.strip()},
        scan_mode=scan_mode,
    )

    # Deterministic quick scan playbook -> task graph.
    tasks = [
        {
            "task_id": "recon_nmap",
            "type": "tool",
            "objective": "Port and service discovery (quick)",
            "dependencies": [],
            "priority": 10,
            "risk_level": "low",
            "timeout_sec": 300 if scan_mode in {"quick", "ci"} else 600,
            "retry_policy": {"max_attempts": 1, "backoff_sec": 0},
            "hitl_required": False,
            "tool": {"name": "nmap", "params": {}},
            "output_contract": {"format": "text", "fields": []},
        },
        {
            "task_id": "fingerprint_whatweb",
            "type": "tool",
            "objective": "Web technology fingerprinting",
            "dependencies": [],
            "priority": 5,
            "risk_level": "low",
            "timeout_sec": 180 if scan_mode in {"quick", "ci"} else 360,
            "retry_policy": {"max_attempts": 1, "backoff_sec": 0},
            "hitl_required": False,
            "tool": {"name": "whatweb", "params": {}},
            "output_contract": {"format": "text", "fields": []},
        },
        {
            "task_id": "report_generate",
            "type": "control",
            "objective": "Generate report (confirmed findings only)",
            "dependencies": ["recon_nmap", "fingerprint_whatweb"],
            "priority": 0,
            "risk_level": "low",
            "timeout_sec": 60,
            "retry_policy": {"max_attempts": 0, "backoff_sec": 0},
            "hitl_required": False,
            "control": {"action": "report_generate", "params": {}},
            "output_contract": {"format": "json", "fields": ["report_artifact_id"]},
        },
    ]
    graph = {"run_id": run["id"], "created_at": _utcnow_iso(), "tasks": tasks}
    schema = _load_task_graph_schema()
    try:
        jsonschema_validate(instance=graph, schema=schema)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Task graph validation failed: {exc}") from exc

    await create_task_graph(run_id=run["id"], graph=graph, schema_version=1)
    await insert_tasks(run_id=run["id"], task_specs=tasks)

    await append_event(run_id=run["id"], event_type="run_created", payload={"run_id": run["id"], "kind": kind})
    await append_event(run_id=run["id"], event_type="tasks_queued", payload={"run_id": run["id"], "count": len(tasks)})

    return run


@router.get("/runs")
async def api_list_runs(
    status: str | None = None,
    kind: str | None = None,
    limit: int = 50,
    offset: int = 0,
    _principal=Depends(require_viewer),
):
    rows = await list_runs(status=status, kind=kind, limit=limit, offset=offset)
    return {"runs": rows}


@router.get("/runs/{run_id}")
async def api_get_run(run_id: str, _principal=Depends(require_viewer)):
    run = await get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    tasks = await list_tasks(run_id=run_id, limit=5000)
    return {"run": run, "tasks": tasks}


@router.post("/runs/{run_id}/stop")
async def api_stop_run(run_id: str, _principal=Depends(require_operator)):
    run = await get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    await mark_run_stopping(run_id)
    cancelled = await cancel_queued_tasks_for_run(run_id=run_id, reason="run_stopping")
    await append_event(run_id=run_id, event_type="run_stopping", payload={"run_id": run_id, "cancelled_queued": cancelled})
    return {"run_id": run_id, "status": "stopping", "cancelled_queued": cancelled}


@router.get("/runs/{run_id}/events")
async def api_run_events(run_id: str, since_seq: int = 0, limit: int = 500, _principal=Depends(require_viewer)):
    run = await get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    events = await list_events(run_id=run_id, since_seq=since_seq, limit=limit)
    return {"run_id": run_id, "events": events}

