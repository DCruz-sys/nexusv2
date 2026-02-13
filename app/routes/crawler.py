"""Crawler control and observability routes."""
from __future__ import annotations

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.config import ENABLE_CRAWLER, MAX_PENDING_CRAWL
from app.database import (
    count_pending_jobs,
    enqueue_job,
    get_latest_learning_run,
    get_crawler_policy_for_domain,
    list_crawl_sources,
    list_crawler_policies,
    list_recent_crawl_extractions,
    upsert_crawler_policy,
)
from app.jobs.runner import job_runner
from app.security.auth import require_operator, require_viewer

router = APIRouter(tags=["crawler"])


class CrawlRunRequest(BaseModel):
    seeds: list[str] = Field(default_factory=list, max_length=100)
    focused: bool = True
    distill_after: bool = False
    max_depth: int | None = Field(default=None, ge=0, le=8)
    max_pages_per_day: int | None = Field(default=None, ge=10, le=10000)
    max_pages_per_domain: int | None = Field(default=None, ge=1, le=2000)
    allow_subdomains: bool | None = None


class CrawlerPolicyRequest(BaseModel):
    domain: str = Field(default="*", min_length=1, max_length=255)
    allow: bool = True
    max_depth: int | None = Field(default=None, ge=0, le=8)
    daily_cap: int | None = Field(default=None, ge=1, le=5000)
    trust_floor: float | None = Field(default=None, ge=0.0, le=1.0)


@router.post("/crawler/run")
async def api_run_crawler(req: CrawlRunRequest, _principal=Depends(require_operator)):
    """Queue a crawl cycle."""
    if not ENABLE_CRAWLER:
        raise HTTPException(status_code=409, detail="Crawler is disabled by feature flag.")

    pending = await count_pending_jobs("crawl")
    if pending >= MAX_PENDING_CRAWL:
        raise HTTPException(
            status_code=429,
            detail=f"Crawler queue is full ({pending}/{MAX_PENDING_CRAWL}).",
        )

    seeds = [s for s in req.seeds if isinstance(s, str) and s.startswith(("http://", "https://"))][:100]
    job_id = await enqueue_job(
        job_type="crawl",
        payload={
            "trigger": "api",
            "seeds": seeds,
            "focused": bool(req.focused),
            "distill_after": bool(req.distill_after),
            "max_depth": req.max_depth,
            "max_pages_per_day": req.max_pages_per_day,
            "max_pages_per_domain": req.max_pages_per_domain,
            "allow_subdomains": req.allow_subdomains,
        },
        max_attempts=2,
    )
    return {"status": "queued", "job_id": job_id}


@router.get("/crawler/status")
async def api_crawler_status(_principal=Depends(require_viewer)):
    """Crawler health and queue state."""
    latest = await get_latest_learning_run(stage="crawl")
    pending = await count_pending_jobs("crawl")
    runner = await job_runner.status()
    return {
        "enabled": ENABLE_CRAWLER,
        "pending_jobs": pending,
        "latest_run": latest,
        "queue": runner.get("queue", {}).get("crawl", {}),
        "latency_ms": runner.get("latency_ms", {}),
    }


@router.get("/crawler/sources")
async def api_crawler_sources(limit: int = 200, _principal=Depends(require_viewer)):
    """Learned source stats with trust scores."""
    capped_limit = max(1, min(limit, 1000))
    sources = await list_crawl_sources(limit=capped_limit)
    extractions = await list_recent_crawl_extractions(limit=500)
    by_domain = {}
    for item in extractions:
        domain = (urlparse(str(item.get("source_url", ""))).hostname or "").lower()
        if domain:
            by_domain[domain] = by_domain.get(domain, 0) + 1
    return {
        "sources": sources,
        "extraction_counts": by_domain,
    }


@router.get("/crawler/policy")
async def api_get_crawler_policy(domain: str | None = None, limit: int = 500, _principal=Depends(require_viewer)):
    if domain:
        policy = await get_crawler_policy_for_domain(domain)
        return {"domain": domain, "policy": policy}
    rows = await list_crawler_policies(limit=max(1, min(limit, 5000)))
    return {"policies": rows}


@router.put("/crawler/policy")
async def api_put_crawler_policy(req: CrawlerPolicyRequest, _principal=Depends(require_operator)):
    await upsert_crawler_policy(
        domain=req.domain.strip().lower(),
        allow=req.allow,
        max_depth=req.max_depth,
        daily_cap=req.daily_cap,
        trust_floor=req.trust_floor,
    )
    return {"status": "updated", "domain": req.domain.strip().lower()}
