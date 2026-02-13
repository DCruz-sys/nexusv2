"""FastAPI application entry point."""
import platform
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
try:
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
except Exception:
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

    def generate_latest() -> bytes:
        return b"# Prometheus client unavailable\n"

from app.config import AUTH_BOOTSTRAP_API_KEY, ENV_NORMALIZED_KEYS, JOB_RUNNER_MODE, KALI_ONLY_ENFORCE
from app.database import (
    add_memory_audit_event,
    backfill_memory_audit_chain,
    get_memory_stats,
    get_queue_stats,
    init_db,
    upsert_api_key,
)
from app.jobs.runner import job_runner
from app.routes import auth, chat, crawler, frameworks, learning, memory, pentest_v3, reports, scans, security, swarm, system, targets
from app.ai.memory_manager import memory_manager
from app.ai.nim_client import NIMClientError, nim_client
from app.ai.nim_retrieval_client import nim_retrieval_client
from app.observability.context import get_correlation_id, set_correlation_id
from app.observability.metrics import (
    HTTP_REQUESTS_TOTAL,
    HTTP_REQUEST_LATENCY_SEC,
    update_memory_metrics,
    update_queue_metrics,
)
from app.system.capabilities import ESSENTIAL_TOOLS, refresh_tool_capabilities
from app.system.platform import is_kali_linux


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize resources on startup."""
    if KALI_ONLY_ENFORCE and not is_kali_linux():
        raise RuntimeError("Kali-only mode is enabled. This service must run on Kali Linux.")
    try:
        await init_db()
    except Exception as exc:
        raise RuntimeError(
            "Database initialization failed. Verify SQLite access and ensure uvloop is installed "
            "for Python 3.13 environments."
        ) from exc
    await backfill_memory_audit_chain()
    if ENV_NORMALIZED_KEYS:
        await add_memory_audit_event(
            event_type="env_normalized",
            actor="startup",
            reason="blank_credentials_policy",
            payload={"keys": ENV_NORMALIZED_KEYS},
        )
    if AUTH_BOOTSTRAP_API_KEY:
        await upsert_api_key(
            name="bootstrap-admin",
            plaintext_key=AUTH_BOOTSTRAP_API_KEY,
            role="admin",
            scopes=["*"],
        )
    # Startup must be fast and reliable; scanning 3k+ Kali tools and persisting all
    # capability rows can take minutes on slower disks. Refresh essentials only here.
    await refresh_tool_capabilities(tool_names=ESSENTIAL_TOOLS)
    await nim_client.start()
    await nim_retrieval_client.start()
    await pentest_v3.startup_pentest_orchestrator()
    if JOB_RUNNER_MODE == "embedded":
        await memory_manager.start()
        await job_runner.start()
    yield
    if JOB_RUNNER_MODE == "embedded":
        await job_runner.stop()
        await memory_manager.stop()
    await pentest_v3.shutdown_pentest_orchestrator()
    await nim_retrieval_client.stop()
    await nim_client.stop()


app = FastAPI(
    title="NexusPenTest",
    description="AI-Powered Penetration Testing Platform",
    version="1.0.0",
    lifespan=lifespan,
)

CORRELATION_HEADER = "X-Correlation-ID"

# Mount static files
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Include routers - chat and scans need root-level for WebSocket (/ws/*)
app.include_router(chat.router)
app.include_router(scans.router)
app.include_router(reports.router, prefix="/api")
app.include_router(frameworks.router, prefix="/api")
app.include_router(memory.router, prefix="/api")
app.include_router(targets.router, prefix="/api")
app.include_router(crawler.router, prefix="/api")
app.include_router(learning.router, prefix="/api")
app.include_router(system.router, prefix="/api")
app.include_router(auth.router, prefix="/api")
app.include_router(security.router, prefix="/api")
app.include_router(swarm.router)
app.include_router(pentest_v3.router)
app.include_router(pentest_v3.compat_router)


@app.middleware("http")
async def prometheus_http_middleware(request: Request, call_next):
    incoming_correlation = (
        request.headers.get(CORRELATION_HEADER)
        or request.headers.get(CORRELATION_HEADER.lower())
        or str(uuid.uuid4())
    )
    set_correlation_id(incoming_correlation)
    start = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = int(getattr(response, "status_code", 500))
        response.headers[CORRELATION_HEADER] = incoming_correlation
        return response
    finally:
        path = request.url.path
        duration = max(0.0, time.perf_counter() - start)
        HTTP_REQUESTS_TOTAL.labels(request.method, path, str(status_code)).inc()
        HTTP_REQUEST_LATENCY_SEC.labels(request.method, path).observe(duration)
        set_correlation_id("")


@app.exception_handler(HTTPException)
async def http_exception_handler(_request: Request, exc: HTTPException):
    detail = exc.detail
    if isinstance(detail, dict):
        code = detail.get("code", "http_error")
        message = detail.get("message", "Request failed.")
        details = detail.get("details", {})
        if not isinstance(details, dict):
            details = {"detail": details}
    else:
        code = "http_error"
        message = str(detail)
        details = {}
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "code": code,
            "message": message,
            "details": {**details, "correlation_id": get_correlation_id()},
        },
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(_request: Request, _exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "code": "internal_error",
            "message": "Internal server error.",
            "details": {"correlation_id": get_correlation_id()},
        },
    )


@app.exception_handler(NIMClientError)
async def nim_exception_handler(_request: Request, exc: NIMClientError):
    return JSONResponse(
        status_code=int(getattr(exc, "status_code", 502) or 502),
        content={
            "code": getattr(exc, "code", "nim_error"),
            "message": str(exc),
            "details": {"correlation_id": get_correlation_id()},
        },
    )


@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "service": "NexusPenTest",
        "version": "1.0.0",
        "platform": platform.system().lower(),
        "kali_only_mode": KALI_ONLY_ENFORCE,
        "kali_detected": is_kali_linux(),
    }


@app.get("/health")
async def compatibility_health_check(response: Response):
    response.headers["X-API-Deprecated"] = "Use /api/health"
    return await health_check()


@app.get("/")
async def serve_index():
    return FileResponse(str(static_dir / "index.html"))


@app.get("/metrics")
async def metrics():
    try:
        update_queue_metrics(await get_queue_stats())
        update_memory_metrics(await get_memory_stats())
    except Exception:
        # Keep /metrics best-effort; exporter should never fail hard.
        pass
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
