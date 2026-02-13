"""Learning pipeline trigger and status routes."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.config import (
    ENABLE_DISTILLATION_PIPELINE,
    LEARNING_DEFAULT_PROFILE,
    LEARNING_SOURCE_BATCH_SIZE,
    MAX_PENDING_CRAWL,
    MAX_PENDING_DISTILL,
)
from app.database import (
    add_learning_source_event,
    count_learning_frontier,
    count_learning_sources,
    count_pending_jobs,
    count_running_jobs_by_type,
    enqueue_job,
    get_latest_learning_run,
    get_learning_checkpoint,
    get_learning_source,
    list_learning_source_events,
    list_learning_sources,
    list_learning_frontier,
    upsert_learning_frontier_url,
    upsert_learning_source,
    update_learning_source,
)
from app.security.auth import require_operator, require_viewer

router = APIRouter(tags=["learning"])


class DistillRequest(BaseModel):
    limit: int = Field(default=300, ge=10, le=2000)


class LearningSourceCreateRequest(BaseModel):
    seed_url: str = Field(min_length=4, max_length=2048)
    profile: str = Field(default=LEARNING_DEFAULT_PROFILE)
    enabled: bool = True
    max_depth: int | None = Field(default=None, ge=0, le=8)
    max_pages_per_domain: int | None = Field(default=None, ge=1, le=2000)
    max_pages_per_day: int | None = Field(default=None, ge=10, le=10000)
    allow_subdomains: bool | None = None
    recrawl_interval_min: int | None = Field(default=None, ge=10, le=10080)


class LearningSourcePatchRequest(BaseModel):
    enabled: bool | None = None
    profile: str | None = None
    max_depth: int | None = Field(default=None, ge=0, le=8)
    max_pages_per_domain: int | None = Field(default=None, ge=1, le=2000)
    max_pages_per_day: int | None = Field(default=None, ge=10, le=10000)
    allow_subdomains: bool | None = None
    recrawl_interval_min: int | None = Field(default=None, ge=10, le=10080)


def _normalize_seed_url(raw: str) -> tuple[str, str]:
    value = (raw or "").strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        parsed = urlparse(f"https://{value}")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return "", ""
    return parsed._replace(fragment="").geturl(), (parsed.hostname or "").strip().lower()


@router.post("/learning/distill")
async def api_trigger_distill(req: DistillRequest, _principal=Depends(require_operator)):
    """Queue a distillation run."""
    if not ENABLE_DISTILLATION_PIPELINE:
        raise HTTPException(status_code=409, detail="Distillation pipeline is disabled.")

    pending = await count_pending_jobs("distill")
    if pending >= MAX_PENDING_DISTILL:
        raise HTTPException(
            status_code=429,
            detail=f"Distillation queue is full ({pending}/{MAX_PENDING_DISTILL}).",
        )

    job_id = await enqueue_job(
        job_type="distill",
        payload={"trigger": "api", "limit": int(req.limit)},
        max_attempts=2,
    )
    return {"status": "queued", "job_id": job_id}


@router.get("/learning/status")
async def api_learning_status(_principal=Depends(require_viewer)):
    """Latest learning pipeline status."""
    latest_any = await get_latest_learning_run()
    latest_crawl = await get_latest_learning_run(stage="crawl")
    latest_distill = await get_latest_learning_run(stage="distill")
    sources_total = await count_learning_sources(enabled_only=False)
    sources_enabled = await count_learning_sources(enabled_only=True)
    frontier_queued = await count_learning_frontier(status="queued")
    active_source_runs = await count_running_jobs_by_type("crawl_source")
    return {
        "latest": latest_any,
        "crawl": latest_crawl,
        "distill": latest_distill,
        "sources_total": sources_total,
        "sources_enabled": sources_enabled,
        "active_source_runs": active_source_runs,
        "frontier_queued": frontier_queued,
        "last_distill_at": latest_distill.get("finished_at") if isinstance(latest_distill, dict) else None,
        "pending_jobs": {
            "crawl": await count_pending_jobs("crawl"),
            "crawl_source": await count_pending_jobs("crawl_source"),
            "distill": await count_pending_jobs("distill"),
            "extract": await count_pending_jobs("extract"),
            "maintenance": await count_pending_jobs("maintenance"),
        },
    }


@router.post("/learning/sources")
async def api_create_learning_source(req: LearningSourceCreateRequest, _principal=Depends(require_operator)):
    seed_url, domain = _normalize_seed_url(req.seed_url)
    if not seed_url or not domain:
        raise HTTPException(status_code=400, detail="Invalid seed URL.")
    source = await upsert_learning_source(
        seed_url=seed_url,
        profile=req.profile,
        enabled=bool(req.enabled),
        max_depth=req.max_depth,
        max_pages_per_domain=req.max_pages_per_domain,
        max_pages_per_day=req.max_pages_per_day,
        allow_subdomains=req.allow_subdomains,
        recrawl_interval_min=req.recrawl_interval_min,
        metadata={"created_via": "api"},
    )
    source_id = str(source.get("id") or "")
    await upsert_learning_frontier_url(
        source_id=source_id,
        url=seed_url,
        domain=domain,
        depth=0,
        priority=100,
        discovered_from=seed_url,
    )
    pending = await count_pending_jobs("crawl_source")
    if pending >= MAX_PENDING_CRAWL:
        raise HTTPException(status_code=429, detail=f"Learning source queue is full ({pending}/{MAX_PENDING_CRAWL}).")
    job_id = await enqueue_job(
        job_type="crawl_source",
        payload={"source_id": source_id, "trigger": "api", "batch_size": LEARNING_SOURCE_BATCH_SIZE},
        max_attempts=2,
    )
    now = datetime.now(timezone.utc)
    await update_learning_source(
        source_id,
        next_run_at=(now + timedelta(seconds=20)).isoformat(),
    )
    await add_learning_source_event(source_id, "learning_source_created", {"seed_url": seed_url, "job_id": job_id})
    return {"status": "queued", "job_id": job_id, "source": source}


@router.get("/learning/sources")
async def api_list_learning_sources(enabled_only: bool = False, limit: int = 100, offset: int = 0, _principal=Depends(require_viewer)):
    rows = await list_learning_sources(enabled_only=enabled_only, limit=max(1, min(limit, 500)), offset=max(0, offset))
    return {"sources": rows}


@router.get("/learning/sources/{source_id}")
async def api_get_learning_source(source_id: str, _principal=Depends(require_viewer)):
    source = await get_learning_source(source_id)
    if not source:
        raise HTTPException(status_code=404, detail="Learning source not found.")
    checkpoint = await get_learning_checkpoint(source_id)
    frontier = {
        "queued": await count_learning_frontier(source_id, status="queued"),
        "running": await count_learning_frontier(source_id, status="running"),
        "done": await count_learning_frontier(source_id, status="done"),
        "error": await count_learning_frontier(source_id, status="error"),
    }
    return {"source": source, "checkpoint": checkpoint, "frontier": frontier}


@router.patch("/learning/sources/{source_id}")
async def api_patch_learning_source(source_id: str, req: LearningSourcePatchRequest, _principal=Depends(require_operator)):
    source = await get_learning_source(source_id)
    if not source:
        raise HTTPException(status_code=404, detail="Learning source not found.")
    updates = {}
    for key in (
        "enabled",
        "profile",
        "max_depth",
        "max_pages_per_domain",
        "max_pages_per_day",
        "allow_subdomains",
        "recrawl_interval_min",
    ):
        val = getattr(req, key)
        if val is not None:
            updates[key] = val
    if not updates:
        return {"status": "no_change", "source": source}
    await update_learning_source(source_id, **updates)
    updated = await get_learning_source(source_id)
    event_type = "learning_source_disabled" if updates.get("enabled") is False else "learning_source_updated"
    await add_learning_source_event(source_id, event_type, {"updates": updates})
    return {"status": "updated", "source": updated}


@router.post("/learning/sources/{source_id}/crawl-now")
async def api_learning_source_crawl_now(source_id: str, _principal=Depends(require_operator)):
    source = await get_learning_source(source_id)
    if not source:
        raise HTTPException(status_code=404, detail="Learning source not found.")
    pending = await count_pending_jobs("crawl_source")
    if pending >= MAX_PENDING_CRAWL:
        raise HTTPException(status_code=429, detail=f"Learning source queue is full ({pending}/{MAX_PENDING_CRAWL}).")
    job_id = await enqueue_job(
        job_type="crawl_source",
        payload={"source_id": source_id, "trigger": "manual", "batch_size": LEARNING_SOURCE_BATCH_SIZE},
        max_attempts=2,
    )
    await update_learning_source(source_id, next_run_at=datetime.now(timezone.utc).isoformat())
    await add_learning_source_event(source_id, "learning_source_crawl_now", {"job_id": job_id})
    return {"status": "queued", "job_id": job_id, "source_id": source_id}


@router.get("/learning/sources/{source_id}/events")
async def api_learning_source_events(source_id: str, limit: int = 200, _principal=Depends(require_viewer)):
    source = await get_learning_source(source_id)
    if not source:
        raise HTTPException(status_code=404, detail="Learning source not found.")
    events = await list_learning_source_events(source_id, limit=max(1, min(limit, 1000)))
    return {"source_id": source_id, "events": events}


@router.get("/learning/sources/{source_id}/frontier")
async def api_learning_source_frontier(source_id: str, status: str | None = None, limit: int = 200, _principal=Depends(require_viewer)):
    source = await get_learning_source(source_id)
    if not source:
        raise HTTPException(status_code=404, detail="Learning source not found.")
    allowed_status = {None, "queued", "running", "done", "error", "skipped"}
    status_norm = (status or "").strip().lower() or None
    if status_norm not in allowed_status:
        raise HTTPException(status_code=400, detail="Invalid frontier status filter.")
    rows = await list_learning_frontier(source_id, status=status_norm, limit=max(1, min(limit, 1000)))
    return {"source_id": source_id, "status": status_norm, "items": rows}
