"""Findings + evidence repository (SQLite)."""

from __future__ import annotations

from typing import Any

from nexus_v2.infra.db.sqlite import get_db
from nexus_v2.infra.repos._common import json_dumps, json_loads, new_id, utcnow_iso


def _row_to_dict(row) -> dict[str, Any]:
    return dict(row) if row else {}


async def create_finding(
    *,
    run_id: str,
    title: str,
    category: str | None = None,
    severity: str | None = None,
    state: str = "hypothesis",
    confidence: float = 0.5,
    summary: str | None = None,
    meta: dict | None = None,
) -> dict:
    fid = new_id("find")
    now = utcnow_iso()
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO findings(id, run_id, title, category, severity, state, confidence, summary, meta_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                fid,
                run_id,
                title.strip(),
                (category or "").strip().lower() or None,
                (severity or "").strip().lower() or None,
                state.strip().lower(),
                float(confidence),
                summary,
                json_dumps(meta or {}),
                now,
                now,
            ),
        )
        await db.commit()
        return {
            "id": fid,
            "run_id": run_id,
            "title": title.strip(),
            "category": (category or "").strip().lower() or None,
            "severity": (severity or "").strip().lower() or None,
            "state": state.strip().lower(),
            "confidence": float(confidence),
            "summary": summary,
            "meta": meta or {},
            "created_at": now,
            "updated_at": now,
        }
    finally:
        await db.close()


async def get_finding(finding_id: str) -> dict | None:
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM findings WHERE id = ? LIMIT 1", (finding_id,))
        row = await cur.fetchone()
        if not row:
            return None
        d = _row_to_dict(row)
        d["meta"] = json_loads(d.get("meta_json"), {})
        d.pop("meta_json", None)
        return d
    finally:
        await db.close()


async def list_findings(*, run_id: str, limit: int = 500) -> list[dict]:
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT * FROM findings WHERE run_id = ? ORDER BY created_at DESC LIMIT ?",
            (run_id, max(1, min(int(limit), 5000))),
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


async def update_finding(
    *,
    finding_id: str,
    state: str | None = None,
    confidence: float | None = None,
    summary: str | None = None,
    meta: dict | None = None,
) -> None:
    now = utcnow_iso()
    db = await get_db()
    try:
        await db.execute(
            "UPDATE findings SET "
            "state = COALESCE(?, state), "
            "confidence = COALESCE(?, confidence), "
            "summary = COALESCE(?, summary), "
            "meta_json = COALESCE(?, meta_json), "
            "updated_at = ? "
            "WHERE id = ?",
            (
                state.strip().lower() if state else None,
                float(confidence) if confidence is not None else None,
                summary,
                json_dumps(meta) if meta is not None else None,
                now,
                finding_id,
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def add_evidence(
    *,
    finding_id: str,
    kind: str,
    artifact_id: str | None = None,
    meta: dict | None = None,
) -> dict:
    evid = new_id("evid")
    now = utcnow_iso()
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO evidence(id, finding_id, kind, artifact_id, meta_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (evid, finding_id, kind.strip().lower(), artifact_id, json_dumps(meta or {}), now),
        )
        await db.commit()
        return {
            "id": evid,
            "finding_id": finding_id,
            "kind": kind.strip().lower(),
            "artifact_id": artifact_id,
            "meta": meta or {},
            "created_at": now,
        }
    finally:
        await db.close()


async def list_evidence(*, finding_id: str, limit: int = 200) -> list[dict]:
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT * FROM evidence WHERE finding_id = ? ORDER BY created_at DESC LIMIT ?",
            (finding_id, max(1, min(int(limit), 2000))),
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

