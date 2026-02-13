"""Engagement repository (SQLite)."""

from __future__ import annotations

from typing import Any

from nexus_v2.infra.db.sqlite import get_db
from nexus_v2.infra.repos._common import new_id, utcnow_iso


def _row_to_dict(row) -> dict[str, Any]:
    return dict(row) if row else {}


async def create_engagement(name: str) -> dict:
    eid = new_id("eng")
    now = utcnow_iso()
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO engagements(id, name, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (eid, name.strip() or "Engagement", now, now),
        )
        await db.commit()
        return {"id": eid, "name": name.strip() or "Engagement", "created_at": now, "updated_at": now}
    finally:
        await db.close()


async def get_engagement(engagement_id: str) -> dict | None:
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM engagements WHERE id = ? LIMIT 1", (engagement_id,))
        row = await cur.fetchone()
        return _row_to_dict(row) if row else None
    finally:
        await db.close()


async def list_engagements(limit: int = 50, offset: int = 0) -> list[dict]:
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT * FROM engagements ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (max(1, min(int(limit), 500)), max(0, int(offset))),
        )
        rows = await cur.fetchall()
        return [_row_to_dict(r) for r in rows]
    finally:
        await db.close()
