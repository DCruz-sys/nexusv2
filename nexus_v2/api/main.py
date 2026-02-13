"""FastAPI entrypoint for Nexus v2."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from nexus_v2.config import get_settings
from nexus_v2.infra.db.sqlite import init_db
from nexus_v2.infra.repos.api_keys import upsert_api_key
from nexus_v2.infra.tools.registry_yaml import tool_registry

from nexus_v2.api.routes.auth import router as auth_router
from nexus_v2.api.routes.engagements import router as engagements_router
from nexus_v2.api.routes.runs import router as runs_router
from nexus_v2.api.routes.artifacts import router as artifacts_router
from nexus_v2.api.routes.findings import router as findings_router
from nexus_v2.api.routes.system import router as system_router
from nexus_v2.api.routes.mcp import router as mcp_router
from nexus_v2.api.ws.runs import stream_run_events


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await init_db()
    tool_registry.load()

    # Optional bootstrap API key (admin) for local ops.
    bootstrap = (os.getenv("AUTH_BOOTSTRAP_API_KEY") or "").strip()
    if bootstrap:
        try:
            await upsert_api_key(name="bootstrap-admin", plaintext_key=bootstrap, role="admin", scopes=["*"])
        except Exception:
            pass

    yield


app = FastAPI(
    title="Nexus v2",
    description="Local-first engagement + run graph pentest platform",
    version="2.0.0",
    lifespan=lifespan,
)

app.include_router(auth_router)
app.include_router(engagements_router)
app.include_router(runs_router)
app.include_router(artifacts_router)
app.include_router(findings_router)
app.include_router(system_router)
app.include_router(mcp_router)


@app.get("/api/v2/health")
async def health():
    return {"status": "ok", "service": "nexus_v2"}


@app.websocket("/ws/v2/runs/{run_id}")
async def ws_runs(websocket, run_id: str):
    await stream_run_events(websocket, run_id)


# Serve v2 static UI (minimal scaffolding; can be expanded).
settings = get_settings()
static_dir = Path(settings.base_dir) / "web_v2" / "static"
if static_dir.exists():
    app.mount("/v2/static", StaticFiles(directory=str(static_dir)), name="v2_static")


@app.get("/v2")
async def serve_v2_index():
    index = static_dir / "index.html"
    if not index.exists():
        return {"available": False, "hint": "web_v2/static/index.html not found"}
    return FileResponse(str(index))
