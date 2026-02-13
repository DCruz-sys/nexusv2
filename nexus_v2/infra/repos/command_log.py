"""Command log repository (SQLite)."""

from __future__ import annotations

from nexus_v2.infra.db.sqlite import get_db
from nexus_v2.infra.repos._common import json_dumps, new_id, utcnow_iso


async def log_command_start(
    *,
    run_id: str,
    task_id: str | None,
    argv: list[str],
    cwd: str | None = None,
    env_redacted: dict | None = None,
) -> str:
    cid = new_id("cmd")
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO command_log(id, run_id, task_id, argv_json, cwd, env_redacted_json, started_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                cid,
                run_id,
                task_id,
                json_dumps(argv),
                cwd,
                json_dumps(env_redacted or {}),
                utcnow_iso(),
            ),
        )
        await db.commit()
        return cid
    finally:
        await db.close()


async def log_command_finish(*, command_log_id: str, rc: int | None) -> None:
    db = await get_db()
    try:
        await db.execute(
            "UPDATE command_log SET completed_at = ?, rc = ? WHERE id = ?",
            (utcnow_iso(), rc, command_log_id),
        )
        await db.commit()
    finally:
        await db.close()

