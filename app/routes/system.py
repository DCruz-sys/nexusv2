"""System metrics and diagnostics routes."""
from __future__ import annotations

import hashlib
import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from app.config import (
    AUTH_ENABLED,
    AUTH_JWT_SECRET,
    ANALYSIS_WORKERS,
    BASE_DIR,
    CRAWLER_WORKERS,
    DEADCODE_REPORT_PATH,
    ENABLE_NATIVE_ACCELERATORS,
    JOB_RUNNER_MODE,
    MAX_CONCURRENT_TOOLS,
    MAX_PENDING_CRAWL,
    MAX_PENDING_DISTILL,
    MAX_PENDING_SCANS,
    NEMO_GUARDRAILS_ENABLED,
    NIM_STATELESS_METADATA,
    NVIDIA_API_KEY,
    LEARNING_SOURCE_DISTILL_MIN_NEW_DOCS,
    REPORTS_DIR,
    RUNTIME_PROFILE,
    SCAN_WORKERS,
    SWARM_MAX_PARALLEL,
    SWARM_TASK_TIMEOUT_SEC,
    WORKER_HEARTBEAT_SEC,
)
from app.ai.guardrails import guardrails_manager
from app.ai.nim_client import nim_client
from app.database import (
    add_memory_audit_event,
    count_learning_frontier,
    count_learning_sources,
    count_running_jobs_by_type,
    get_worker_heartbeat,
    get_db,
    get_latest_learning_run,
    get_memory_checkpoints,
    get_memory_stats,
    get_queue_stats,
    get_scan,
    get_scan_results,
    list_api_keys,
    list_scan_jobs,
    list_tool_capabilities,
    verify_memory_audit_chain,
)
from app.jobs.runner import job_runner
from app.observability.metrics import update_memory_metrics, update_queue_metrics
from app.security.auth import require_admin, require_viewer
from app.system.capabilities import get_capability_summary
from app.system.platform import is_kali_linux

router = APIRouter(tags=["system"])

_SECRET_PLACEHOLDERS = {"", "change-me", "change-me-in-production", "default", "secret", "password"}
_PLANNER_SCHEMA_PATH = Path(BASE_DIR) / "schemas" / "planner_task_graph.schema.json"


def _is_secret_default(value: str) -> bool:
    normalized = (value or "").strip().lower()
    return normalized in _SECRET_PLACEHOLDERS or normalized.startswith("change-me")


def _sha256_json(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(dt: str | None) -> datetime | None:
    if not dt:
        return None
    try:
        parsed = datetime.fromisoformat(str(dt))
    except Exception:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@router.get("/system/worker")
async def api_system_worker(_principal=Depends(require_viewer)):
    hb = await get_worker_heartbeat(role="worker")
    updated = _parse_iso(hb.get("updated_at") if hb else None) if hb else None
    age_sec = None
    if updated:
        age_sec = max(0.0, (datetime.now(timezone.utc) - updated).total_seconds())
    stale_after = max(60, int(WORKER_HEARTBEAT_SEC) * 3)
    ok = bool(hb) and age_sec is not None and age_sec <= stale_after
    return {
        "mode": JOB_RUNNER_MODE,
        "ok": ok,
        "stale_after_sec": stale_after,
        "age_sec": int(age_sec) if age_sec is not None else None,
        "heartbeat": hb,
    }


@router.get("/system/planner-schema")
async def api_system_planner_schema(_principal=Depends(require_viewer)):
    """Return planner->agent task graph JSON schema."""
    if not _PLANNER_SCHEMA_PATH.exists():
        return {"available": False, "path": str(_PLANNER_SCHEMA_PATH)}
    try:
        payload = json.loads(_PLANNER_SCHEMA_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"available": False, "path": str(_PLANNER_SCHEMA_PATH), "error": str(exc)}
    return {"available": True, "path": str(_PLANNER_SCHEMA_PATH), "schema": payload}


@router.get("/system/perf")
async def api_system_perf(_principal=Depends(require_viewer)):
    """Current performance metrics and accelerator usage."""
    runner = await job_runner.status()
    queue = await get_queue_stats()
    memory = await get_memory_stats()
    capabilities = await get_capability_summary()
    update_queue_metrics(queue)
    update_memory_metrics(memory)
    return {
        "timestamp": int(time.time()),
        "platform": platform.platform(),
        "runtime_profile": RUNTIME_PROFILE,
        "native_accelerators_enabled": ENABLE_NATIVE_ACCELERATORS,
        "job_runner": runner,
        "queue": queue,
        "memory": memory,
        "capabilities": capabilities,
    }


@router.get("/system/deadcode-report")
async def api_deadcode_report(_principal=Depends(require_viewer)):
    """Return dead code/static analysis report artifact from CI if available."""
    if not DEADCODE_REPORT_PATH.exists():
        return {
            "available": False,
            "path": str(DEADCODE_REPORT_PATH),
            "report": {
                "summary": "No deadcode report artifact found.",
                "hint": "Generate .runtime/reports/deadcode_report.json during CI and expose it here.",
            },
        }

    try:
        payload = json.loads(DEADCODE_REPORT_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "available": False,
            "path": str(DEADCODE_REPORT_PATH),
            "error": f"Failed to parse report: {exc}",
        }
    return {"available": True, "path": str(DEADCODE_REPORT_PATH), "report": payload}


@router.get("/system/readiness")
async def api_system_readiness(_principal=Depends(require_viewer)):
    """Dependency-aware readiness checks for production deployments."""
    checks = {
        "kali_platform": {"ok": is_kali_linux()},
        "database": {"ok": False},
        "api_keys": {"ok": False},
        "auth_secret": {"ok": False},
        "accelerators": {"ok": True},
        "audit_chain": {"ok": False},
        "nim_api_key": {"ok": bool((NVIDIA_API_KEY or "").strip())},
        "nim_connectivity": {"ok": False},
        "guardrails": {"ok": False},
        "worker": {"ok": False},
        "swarm_workers": {"ok": False},
        "queue_pressure": {"ok": True},
        "runtime_profile": {"ok": RUNTIME_PROFILE == "kali_8gb_balanced", "value": RUNTIME_PROFILE},
        "profile_tuning": {"ok": False},
        "learning_sources": {"ok": True},
        "frontier_queue_pressure": {"ok": True},
        "distillation_lag": {"ok": True},
    }

    try:
        db = await get_db()
        try:
            cursor = await db.execute("SELECT 1 AS ok")
            row = await cursor.fetchone()
            checks["database"]["ok"] = bool(row and int(row["ok"]) == 1)
        finally:
            await db.close()
    except Exception as exc:
        checks["database"]["error"] = str(exc)

    try:
        if not AUTH_ENABLED:
            checks["api_keys"]["ok"] = True
            checks["api_keys"]["active"] = 0
            checks["api_keys"]["mode"] = "disabled"
        else:
            keys = await list_api_keys(limit=20)
            active = [k for k in keys if not k.get("revoked_at")]
            checks["api_keys"]["ok"] = len(active) > 0
            checks["api_keys"]["active"] = len(active)
    except Exception as exc:
        checks["api_keys"]["error"] = str(exc)

    checks["auth_secret"]["ok"] = not _is_secret_default(AUTH_JWT_SECRET)

    try:
        caps = await list_tool_capabilities(limit=2000)
        cap_map = {row.get("tool_name"): row for row in caps}
        checks["accelerators"]["memory_ranker"] = bool(
            cap_map.get("memory_ranker") and int(cap_map["memory_ranker"].get("available") or 0) == 1
        )
        checks["accelerators"]["swarm_planner"] = bool(
            cap_map.get("swarm_planner") and int(cap_map["swarm_planner"].get("available") or 0) == 1
        )
    except Exception as exc:
        checks["accelerators"]["ok"] = False
        checks["accelerators"]["error"] = str(exc)

    try:
        audit_check = await verify_memory_audit_chain(limit=2000)
        checks["audit_chain"]["ok"] = bool(audit_check.get("valid"))
        checks["audit_chain"]["checked"] = int(audit_check.get("checked", 0))
        checks["audit_chain"]["broken"] = int(audit_check.get("broken", 0))
    except Exception as exc:
        checks["audit_chain"]["error"] = str(exc)

    try:
        status = guardrails_manager.status()
        checks["guardrails"]["enabled"] = bool(NEMO_GUARDRAILS_ENABLED)
        checks["guardrails"]["nemo_loaded"] = bool(status.nemo_loaded)
        checks["guardrails"]["config_path"] = status.config_path
        checks["guardrails"]["stateless_metadata"] = bool(NIM_STATELESS_METADATA)
        checks["guardrails"]["ok"] = bool(status.enabled)
    except Exception as exc:
        checks["guardrails"]["error"] = str(exc)

    if checks["nim_api_key"]["ok"]:
        try:
            client = await nim_client._get_client()
            resp = await client.get(
                f"{nim_client.base_url}/models",
                headers=nim_client._get_headers(operation="readiness_probe"),
            )
            checks["nim_connectivity"]["ok"] = bool(resp.status_code == 200)
            checks["nim_connectivity"]["status_code"] = int(resp.status_code)
        except Exception as exc:
            checks["nim_connectivity"]["error"] = str(exc)
    else:
        checks["nim_connectivity"]["error"] = "missing_nvidia_api_key"

    try:
        runner = await job_runner.status()
        checks["swarm_workers"]["scan_workers"] = SCAN_WORKERS
        checks["swarm_workers"]["crawler_workers"] = CRAWLER_WORKERS
        checks["swarm_workers"]["analysis_workers"] = ANALYSIS_WORKERS
        if JOB_RUNNER_MODE == "embedded":
            checks["swarm_workers"]["ok"] = bool(runner.get("running"))
        else:
            checks["swarm_workers"]["ok"] = True
    except Exception as exc:
        checks["swarm_workers"]["error"] = str(exc)

    # External worker heartbeat check (or embedded runner presence).
    try:
        if JOB_RUNNER_MODE == "embedded":
            runner = await job_runner.status()
            checks["worker"]["ok"] = bool(runner.get("running"))
            checks["worker"]["mode"] = "embedded"
        else:
            hb = await get_worker_heartbeat(role="worker")
            updated = _parse_iso(hb.get("updated_at") if hb else None) if hb else None
            age_sec = None
            if updated:
                age_sec = max(0.0, (datetime.now(timezone.utc) - updated).total_seconds())
            stale_after = max(60, int(WORKER_HEARTBEAT_SEC) * 3)
            checks["worker"].update(
                {
                    "mode": "external",
                    "stale_after_sec": stale_after,
                    "age_sec": int(age_sec) if age_sec is not None else None,
                    "worker_id": hb.get("worker_id") if hb else None,
                }
            )
            checks["worker"]["ok"] = bool(hb) and age_sec is not None and age_sec <= stale_after
    except Exception as exc:
        checks["worker"]["error"] = str(exc)

    try:
        queue_stats = await get_queue_stats()

        def _pending(job_type: str) -> int:
            bucket = queue_stats.get(job_type, {}) if isinstance(queue_stats, dict) else {}
            return int(bucket.get("queued", 0) or 0) + int(bucket.get("running", 0) or 0)

        pending_scans = _pending("scan")
        pending_crawl = _pending("crawl")
        pending_distill = _pending("distill")
        pending_swarm = _pending("swarm")
        swarm_limit = max(10, MAX_PENDING_SCANS)
        checks["queue_pressure"].update(
            {
                "scan": {"pending": pending_scans, "limit": MAX_PENDING_SCANS},
                "crawl": {"pending": pending_crawl, "limit": MAX_PENDING_CRAWL},
                "distill": {"pending": pending_distill, "limit": MAX_PENDING_DISTILL},
                "swarm": {"pending": pending_swarm, "limit": swarm_limit},
            }
        )
        checks["queue_pressure"]["ok"] = (
            pending_scans <= MAX_PENDING_SCANS
            and pending_crawl <= MAX_PENDING_CRAWL
            and pending_distill <= MAX_PENDING_DISTILL
            and pending_swarm <= swarm_limit
        )
    except Exception as exc:
        checks["queue_pressure"]["ok"] = False
        checks["queue_pressure"]["error"] = str(exc)

    try:
        total_sources = await count_learning_sources(enabled_only=False)
        enabled_sources = await count_learning_sources(enabled_only=True)
        running_source_jobs = await count_running_jobs_by_type("crawl_source")
        checks["learning_sources"].update(
            {
                "total": total_sources,
                "enabled": enabled_sources,
                "running_jobs": running_source_jobs,
            }
        )
        checks["learning_sources"]["ok"] = total_sources >= 0 and enabled_sources >= 0
    except Exception as exc:
        checks["learning_sources"]["ok"] = False
        checks["learning_sources"]["error"] = str(exc)

    try:
        frontier_queued = await count_learning_frontier(status="queued")
        frontier_running = await count_learning_frontier(status="running")
        frontier_limit = max(50, MAX_PENDING_CRAWL * 50)
        checks["frontier_queue_pressure"].update(
            {
                "queued": frontier_queued,
                "running": frontier_running,
                "limit": frontier_limit,
            }
        )
        checks["frontier_queue_pressure"]["ok"] = frontier_queued <= frontier_limit
    except Exception as exc:
        checks["frontier_queue_pressure"]["ok"] = False
        checks["frontier_queue_pressure"]["error"] = str(exc)

    try:
        latest_distill = await get_latest_learning_run(stage="distill")
        if not latest_distill or not latest_distill.get("finished_at"):
            checks["distillation_lag"]["ok"] = False
            checks["distillation_lag"]["reason"] = "never_distilled"
        else:
            finished = datetime.fromisoformat(str(latest_distill["finished_at"]))
            hours = (datetime.now(timezone.utc) - finished).total_seconds() / 3600.0
            lag_limit_h = 48 if LEARNING_SOURCE_DISTILL_MIN_NEW_DOCS > 0 else 72
            checks["distillation_lag"]["hours_since_last"] = round(max(0.0, hours), 2)
            checks["distillation_lag"]["limit_hours"] = lag_limit_h
            checks["distillation_lag"]["ok"] = hours <= lag_limit_h
    except Exception as exc:
        checks["distillation_lag"]["ok"] = False
        checks["distillation_lag"]["error"] = str(exc)

    profile_expected = {
        "scan_workers": 1,
        "crawler_workers": 1,
        "analysis_workers": 1,
        "max_concurrent_tools": 2,
        "swarm_max_parallel": 4,
        "swarm_task_timeout_sec": 90,
    }
    profile_actual = {
        "scan_workers": SCAN_WORKERS,
        "crawler_workers": CRAWLER_WORKERS,
        "analysis_workers": ANALYSIS_WORKERS,
        "max_concurrent_tools": MAX_CONCURRENT_TOOLS,
        "swarm_max_parallel": SWARM_MAX_PARALLEL,
        "swarm_task_timeout_sec": SWARM_TASK_TIMEOUT_SEC,
    }
    checks["profile_tuning"]["expected"] = profile_expected
    checks["profile_tuning"]["actual"] = profile_actual
    checks["profile_tuning"]["ok"] = all(
        int(profile_actual.get(key, 0)) <= int(profile_expected.get(key, 0))
        for key in profile_expected
    )

    ready = all(v.get("ok", False) for v in checks.values())
    return {"ready": ready, "checks": checks, "timestamp": int(time.time())}


@router.get("/system/forensics/{scan_id}")
async def api_system_forensics(scan_id: str, _principal=Depends(require_admin)):
    """Build and persist a deterministic forensic bundle for one scan run."""
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": "Scan not found.", "details": {"scan_id": scan_id}},
        )

    results = await get_scan_results(scan_id)
    jobs = await list_scan_jobs(scan_id, limit=500)
    checkpoints = await get_memory_checkpoints(session_id=scan_id, limit=500)
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM memory_audit_log
               WHERE session_id = ? OR json_extract(payload, '$.scan_id') = ?
               ORDER BY id ASC
               LIMIT 5000""",
            (scan_id, scan_id),
        )
        audit_rows = [dict(r) for r in await cursor.fetchall()]
    finally:
        await db.close()

    for row in audit_rows:
        payload_raw = row.get("payload")
        if isinstance(payload_raw, str):
            try:
                row["payload"] = json.loads(payload_raw)
            except Exception:
                pass

    section_hashes = {
        "scan": _sha256_json(scan),
        "results": _sha256_json(results),
        "jobs": _sha256_json(jobs),
        "checkpoints": _sha256_json(checkpoints),
        "audit": _sha256_json(audit_rows),
    }
    audit_integrity = await verify_memory_audit_chain(limit=200000)

    bundle = {
        "manifest_version": 1,
        "scan_id": scan_id,
        "exported_at": _utcnow().isoformat(),
        "section_hashes": section_hashes,
        "audit_integrity": audit_integrity,
        "artifacts": {
            "scan": scan,
            "results": results,
            "jobs": jobs,
            "checkpoints": checkpoints,
            "audit_events": audit_rows,
        },
    }
    bundle_hash = _sha256_json(bundle)

    forensic_dir = Path(REPORTS_DIR) / "forensics"
    forensic_dir.mkdir(parents=True, exist_ok=True)
    filename = f"forensics_{scan_id[:8]}_{_utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = forensic_dir / filename
    filepath.write_text(json.dumps(bundle, indent=2, default=str), encoding="utf-8")

    await add_memory_audit_event(
        event_type="forensics_export",
        actor="system_api",
        session_id=scan_id,
        reason="forensics_bundle_generation",
        payload={
            "scan_id": scan_id,
            "file": str(filepath),
            "bundle_hash": bundle_hash,
            "sections": {k: len(v) if isinstance(v, list) else 1 for k, v in {
                "results": results,
                "jobs": jobs,
                "checkpoints": checkpoints,
                "audit_events": audit_rows,
            }.items()},
        },
    )

    return {
        "scan_id": scan_id,
        "file": str(filepath),
        "bundle_hash": bundle_hash,
        "section_hashes": section_hashes,
        "audit_integrity": audit_integrity,
    }
