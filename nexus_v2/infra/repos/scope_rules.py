"""Scope rules repository (SQLite)."""

from __future__ import annotations

from typing import Any

from nexus_v2.infra.db.sqlite import get_db
from nexus_v2.infra.repos._common import new_id, utcnow_iso


def _row_to_dict(row) -> dict[str, Any]:
    return dict(row) if row else {}


async def add_scope_rule(
    *,
    engagement_id: str,
    rule_type: str,
    pattern: str,
    enabled: bool = True,
) -> dict:
    rid = new_id("scope")
    now = utcnow_iso()
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO scope_rules(id, engagement_id, type, pattern, enabled, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (rid, engagement_id, rule_type.strip().lower(), pattern.strip(), 1 if enabled else 0, now),
        )
        await db.commit()
        return {
            "id": rid,
            "engagement_id": engagement_id,
            "type": rule_type.strip().lower(),
            "pattern": pattern.strip(),
            "enabled": 1 if enabled else 0,
            "created_at": now,
        }
    finally:
        await db.close()


async def list_scope_rules(
    *,
    engagement_id: str,
    enabled_only: bool = False,
    limit: int = 500,
    offset: int = 0,
) -> list[dict]:
    db = await get_db()
    try:
        sql = "SELECT * FROM scope_rules WHERE engagement_id = ?"
        params: list[Any] = [engagement_id]
        if enabled_only:
            sql += " AND enabled = 1"
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([max(1, min(int(limit), 2000)), max(0, int(offset))])
        cur = await db.execute(sql, tuple(params))
        rows = await cur.fetchall()
        return [_row_to_dict(r) for r in rows]
    finally:
        await db.close()

