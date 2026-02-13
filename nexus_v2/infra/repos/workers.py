"""Worker heartbeat repository (SQLite)."""

from __future__ import annotations

from nexus_v2.infra.db.sqlite import get_db
from nexus_v2.infra.repos._common import json_dumps, utcnow_iso


async def upsert_worker_heartbeat(*, worker_id: str, role: str, meta: dict | None = None) -> None:
    db = await get_db()
    try:
        now = utcnow_iso()
        await db.execute(
            "INSERT INTO worker_heartbeats(worker_id, role, updated_at, meta_json) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(worker_id) DO UPDATE SET updated_at=excluded.updated_at, meta_json=excluded.meta_json",
            (worker_id, role, now, json_dumps(meta or {})),
        )
        await db.commit()
    finally:
        await db.close()


async def get_latest_worker_heartbeat(*, role: str = "worker") -> dict | None:
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT * FROM worker_heartbeats WHERE role = ? ORDER BY updated_at DESC LIMIT 1",
            (role,),
        )
        row = await cur.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()
