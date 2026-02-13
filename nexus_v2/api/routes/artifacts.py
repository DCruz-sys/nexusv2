"""Artifact routes (v2)."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from nexus_v2.api.auth import require_viewer
from nexus_v2.infra.repos.artifacts import get_artifact, list_artifacts
from nexus_v2.infra.repos.runs import get_run


router = APIRouter(prefix="/api/v2", tags=["artifacts"])


@router.get("/runs/{run_id}/artifacts")
async def api_list_artifacts(run_id: str, limit: int = 200, _principal=Depends(require_viewer)):
    if not await get_run(run_id):
        raise HTTPException(status_code=404, detail="Run not found")
    rows = await list_artifacts(run_id=run_id, limit=limit)
    return {"run_id": run_id, "artifacts": rows}


@router.get("/runs/{run_id}/artifacts/{artifact_id}")
async def api_get_artifact_chunk(
    run_id: str,
    artifact_id: str,
    offset: int = 0,
    limit: int = 64_000,
    _principal=Depends(require_viewer),
):
    art = await get_artifact(artifact_id)
    if not art or str(art.get("run_id") or "") != run_id:
        raise HTTPException(status_code=404, detail="Artifact not found")
    path = Path(str(art.get("path") or ""))
    if not path.exists():
        raise HTTPException(status_code=404, detail="Artifact file missing on disk")

    start = max(0, int(offset))
    size = max(1, min(int(limit), 512_000))
    with path.open("rb") as f:
        f.seek(start)
        data = f.read(size)

    # Best-effort decode; return bytes if not UTF-8.
    try:
        text = data.decode("utf-8", errors="replace")
        return Response(content=text, media_type="text/plain; charset=utf-8")
    except Exception:
        return Response(content=data, media_type="application/octet-stream")

