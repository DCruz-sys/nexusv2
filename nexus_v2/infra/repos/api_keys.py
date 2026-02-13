"""API key repository (SQLite)."""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

from nexus_v2.infra.db.sqlite import get_db
from nexus_v2.infra.repos._common import json_dumps, json_loads, new_id, utcnow_iso


def hash_api_key(key: str) -> str:
    return hashlib.sha256((key or "").encode("utf-8")).hexdigest()


def _row_to_dict(row) -> dict[str, Any]:
    return dict(row) if row else {}


async def get_api_key_by_hash(key_hash: str) -> dict | None:
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM api_keys WHERE key_hash = ? LIMIT 1", (key_hash,))
        row = await cur.fetchone()
        if not row:
            return None
        d = _row_to_dict(row)
        d["scopes"] = json_loads(d.get("scopes"), [])
        return d
    finally:
        await db.close()


async def upsert_api_key(
    *,
    name: str,
    plaintext_key: str,
    role: str,
    scopes: Iterable[str] | None = None,
) -> dict:
    now = utcnow_iso()
    kid = new_id("key")
    key_hash = hash_api_key(plaintext_key)
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO api_keys(id, name, key_hash, role, scopes, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET key_hash=excluded.key_hash, role=excluded.role, scopes=excluded.scopes",
            (kid, name, key_hash, role.strip().lower(), json_dumps(list(scopes or [])), now),
        )
        await db.commit()
        return {"id": kid, "name": name, "key_hash": key_hash, "role": role.strip().lower(), "scopes": list(scopes or [])}
    finally:
        await db.close()
