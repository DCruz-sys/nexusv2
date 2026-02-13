"""Runs repository (SQLite)."""

from __future__ import annotations

from typing import Any

from nexus_v2.infra.db.sqlite import get_db
from nexus_v2.infra.repos._common import json_dumps, json_loads, new_id, utcnow_iso


def _row_to_dict(row) -> dict[str, Any]:
    return dict(row) if row else {}


async def create_run(
    *,
    engagement_id: str,
    kind: str,
    target: dict,
    scan_mode: str | None = None,
) -> dict:
    run_id = new_id("run")
    now = utcnow_iso()
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO runs(id, engagement_id, kind, target_json, scan_mode, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                engagement_id,
                kind.strip().lower(),
                json_dumps(target),
                (scan_mode or "").strip().lower() or None,
                "queued",
                now,
            ),
        )
        await db.commit()
        return {
            "id": run_id,
            "engagement_id": engagement_id,
            "kind": kind.strip().lower(),
            "target": target,
            "scan_mode": (scan_mode or "").strip().lower() or None,
            "status": "queued",
            "created_at": now,
            "started_at": None,
            "completed_at": None,
            "error": None,
        }
    finally:
        await db.close()


async def get_run(run_id: str) -> dict | None:
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM runs WHERE id = ? LIMIT 1", (run_id,))
        row = await cur.fetchone()
        if not row:
            return None
        out = _row_to_dict(row)
        out["target"] = json_loads(out.get("target_json"), {})
        out.pop("target_json", None)
        return out
    finally:
        await db.close()


async def get_run_status(run_id: str) -> str | None:
    db = await get_db()
    try:
        cur = await db.execute("SELECT status FROM runs WHERE id = ? LIMIT 1", (run_id,))
        row = await cur.fetchone()
        return str(row["status"]) if row else None
    finally:
        await db.close()


async def list_runs(
    *,
    status: str | None = None,
    kind: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    db = await get_db()
    try:
        clauses = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status.strip().lower())
        if kind:
            clauses.append("kind = ?")
            params.append(kind.strip().lower())
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM runs {where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
        cur = await db.execute(sql, tuple(params))
        rows = await cur.fetchall()
        out = []
        for row in rows:
            d = _row_to_dict(row)
            d["target"] = json_loads(d.get("target_json"), {})
            d.pop("target_json", None)
            out.append(d)
        return out
    finally:
        await db.close()


async def update_run_status(
    *,
    run_id: str,
    status: str,
    error: str | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
) -> None:
    db = await get_db()
    try:
        await db.execute(
            "UPDATE runs SET status = ?, error = COALESCE(?, error), "
            "started_at = COALESCE(?, started_at), completed_at = COALESCE(?, completed_at) "
            "WHERE id = ?",
            (status.strip().lower(), error, started_at, completed_at, run_id),
        )
        await db.commit()
    finally:
        await db.close()


async def mark_run_stopping(run_id: str) -> None:
    await update_run_status(run_id=run_id, status="stopping")
