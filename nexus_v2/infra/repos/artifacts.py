"""Artifacts repository (SQLite)."""

from __future__ import annotations

from typing import Any

from nexus_v2.infra.db.sqlite import get_db
from nexus_v2.infra.repos._common import json_dumps, json_loads, new_id, utcnow_iso


def _row_to_dict(row) -> dict[str, Any]:
    return dict(row) if row else {}


async def add_artifact(
    *,
    run_id: str,
    task_id: str | None,
    kind: str,
    path: str,
    sha256: str,
    size_bytes: int,
    meta: dict | None = None,
) -> dict:
    aid = new_id("art")
    now = utcnow_iso()
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO artifacts(id, run_id, task_id, kind, path, sha256, size_bytes, created_at, meta_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                aid,
                run_id,
                task_id,
                kind,
                path,
                sha256,
                int(size_bytes),
                now,
                json_dumps(meta or {}),
            ),
        )
        await db.commit()
        return {
            "id": aid,
            "run_id": run_id,
            "task_id": task_id,
            "kind": kind,
            "path": path,
            "sha256": sha256,
            "size_bytes": int(size_bytes),
            "created_at": now,
            "meta": meta or {},
        }
    finally:
        await db.close()


async def get_artifact(artifact_id: str) -> dict | None:
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM artifacts WHERE id = ? LIMIT 1", (artifact_id,))
        row = await cur.fetchone()
        if not row:
            return None
        d = _row_to_dict(row)
        d["meta"] = json_loads(d.get("meta_json"), {})
        d.pop("meta_json", None)
        return d
    finally:
        await db.close()


async def list_artifacts(*, run_id: str, limit: int = 200) -> list[dict]:
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT * FROM artifacts WHERE run_id = ? ORDER BY created_at DESC LIMIT ?",
            (run_id, max(1, min(int(limit), 2000))),
        )
        rows = await cur.fetchall()
        out = []
        for row in rows:
            d = _row_to_dict(row)
            d["meta"] = json_loads(d.get("meta_json"), {})
            d.pop("meta_json", None)
            out.append(d)
        return out
    finally:
        await db.close()

