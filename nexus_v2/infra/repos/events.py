"""Run events repository (SQLite, append-only)."""

from __future__ import annotations

from typing import Any

from nexus_v2.core.usecases.redaction import redact_text
from nexus_v2.infra.db.sqlite import get_db
from nexus_v2.infra.repos._common import json_dumps, json_loads, utcnow_iso


def _row_to_dict(row) -> dict[str, Any]:
    return dict(row) if row else {}


async def append_event(*, run_id: str, event_type: str, payload: dict) -> dict:
    """Append an event and return the stored row (including seq)."""
    now = utcnow_iso()
    payload_json = json_dumps(payload)
    redacted_json = redact_text(payload_json)

    db = await get_db()
    try:
        await db.execute("BEGIN IMMEDIATE")

        await db.execute(
            "INSERT OR IGNORE INTO run_event_counters(run_id, next_seq) VALUES (?, 1)",
            (run_id,),
        )
        cur = await db.execute("SELECT next_seq FROM run_event_counters WHERE run_id = ? LIMIT 1", (run_id,))
        row = await cur.fetchone()
        seq = int(row["next_seq"]) if row else 1

        await db.execute(
            "UPDATE run_event_counters SET next_seq = ? WHERE run_id = ?",
            (seq + 1, run_id),
        )
        await db.execute(
            "INSERT INTO events(run_id, seq, type, payload_json, redacted_payload_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (run_id, seq, event_type, payload_json, redacted_json, now),
        )
        await db.commit()
        return {"run_id": run_id, "seq": seq, "type": event_type, "payload": payload, "created_at": now}
    except Exception:
        try:
            await db.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        await db.close()


async def list_events(*, run_id: str, since_seq: int = 0, limit: int = 500) -> list[dict]:
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT run_id, seq, type, redacted_payload_json, created_at "
            "FROM events WHERE run_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
            (run_id, max(0, int(since_seq)), max(1, min(int(limit), 5000))),
        )
        rows = await cur.fetchall()
        out = []
        for row in rows:
            d = _row_to_dict(row)
            d["payload"] = json_loads(d.get("redacted_payload_json"), {})
            d.pop("redacted_payload_json", None)
            out.append(d)
        return out
    finally:
        await db.close()
