"""Task graph + tasks repository (SQLite)."""

from __future__ import annotations

from typing import Any

from nexus_v2.infra.db.sqlite import get_db
from nexus_v2.infra.repos._common import json_dumps, json_loads, new_id, utcnow_iso


def _row_to_dict(row) -> dict[str, Any]:
    return dict(row) if row else {}


async def create_task_graph(*, run_id: str, graph: dict, schema_version: int = 1) -> dict:
    gid = new_id("graph")
    now = utcnow_iso()
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO task_graphs(id, run_id, graph_json, schema_version, created_at) VALUES (?, ?, ?, ?, ?)",
            (gid, run_id, json_dumps(graph), int(schema_version), now),
        )
        await db.commit()
        return {"id": gid, "run_id": run_id, "schema_version": int(schema_version), "created_at": now}
    finally:
        await db.close()


async def insert_tasks(*, run_id: str, task_specs: list[dict]) -> list[dict]:
    now = utcnow_iso()
    db = await get_db()
    out = []
    try:
        for spec in task_specs:
            tid = new_id("task")
            task_id = str(spec.get("task_id") or "").strip()
            task_type = str(spec.get("type") or "").strip().lower()
            deps = list(spec.get("dependencies") or [])
            priority = int(spec.get("priority") or 0)
            timeout_sec = int(spec.get("timeout_sec") or 90)
            max_attempts = int((spec.get("retry_policy") or {}).get("max_attempts") or 1)
            await db.execute(
                "INSERT INTO tasks("
                "id, run_id, task_id, type, status, deps_json, spec_json, priority, timeout_sec, attempt, max_attempts, created_at"
                ") VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?, 0, ?, ?)",
                (
                    tid,
                    run_id,
                    task_id,
                    task_type,
                    json_dumps(deps),
                    json_dumps(spec),
                    priority,
                    timeout_sec,
                    max_attempts,
                    now,
                ),
            )
            out.append(
                {
                    "id": tid,
                    "run_id": run_id,
                    "task_id": task_id,
                    "type": task_type,
                    "status": "queued",
                    "dependencies": deps,
                    "priority": priority,
                    "timeout_sec": timeout_sec,
                    "attempt": 0,
                    "max_attempts": max_attempts,
                    "created_at": now,
                }
            )
        await db.commit()
        return out
    finally:
        await db.close()


async def list_tasks(*, run_id: str, limit: int = 500) -> list[dict]:
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT * FROM tasks WHERE run_id = ? ORDER BY created_at ASC LIMIT ?",
            (run_id, max(1, min(int(limit), 5000))),
        )
        rows = await cur.fetchall()
        out = []
        for row in rows:
            d = _row_to_dict(row)
            d["dependencies"] = json_loads(d.get("deps_json"), [])
            d["spec"] = json_loads(d.get("spec_json"), {})
            d.pop("deps_json", None)
            d.pop("spec_json", None)
            out.append(d)
        return out
    finally:
        await db.close()


async def get_task(*, run_id: str, task_id: str) -> dict | None:
    db = await get_db()
    try:
        cur = await db.execute(
            "SELECT * FROM tasks WHERE run_id = ? AND task_id = ? LIMIT 1",
            (run_id, task_id),
        )
        row = await cur.fetchone()
        if not row:
            return None
        d = _row_to_dict(row)
        d["dependencies"] = json_loads(d.get("deps_json"), [])
        d["spec"] = json_loads(d.get("spec_json"), {})
        d.pop("deps_json", None)
        d.pop("spec_json", None)
        return d
    finally:
        await db.close()


async def update_task_status(
    *,
    run_id: str,
    task_id: str,
    status: str,
    error: str | None = None,
    result: dict | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    attempt: int | None = None,
) -> None:
    db = await get_db()
    try:
        await db.execute(
            "UPDATE tasks SET status = ?, "
            "error = CASE WHEN ? IS NULL THEN error ELSE ? END, "
            "result_json = CASE WHEN ? IS NULL THEN result_json ELSE ? END, "
            "started_at = COALESCE(?, started_at), "
            "completed_at = COALESCE(?, completed_at), "
            "attempt = COALESCE(?, attempt) "
            "WHERE run_id = ? AND task_id = ?",
            (
                status,
                error,
                error,
                json_dumps(result) if result is not None else None,
                json_dumps(result) if result is not None else None,
                started_at,
                completed_at,
                attempt,
                run_id,
                task_id,
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def cancel_task(*, run_id: str, task_id: str, reason: str) -> None:
    await update_task_status(run_id=run_id, task_id=task_id, status="cancelled", error=reason)


async def cancel_queued_tasks_for_run(*, run_id: str, reason: str = "run_stopping") -> int:
    db = await get_db()
    try:
        cur = await db.execute(
            "UPDATE tasks SET status='cancelled', error=? WHERE run_id=? AND status='queued'",
            (reason, run_id),
        )
        await db.commit()
        return int(getattr(cur, "rowcount", 0) or 0)
    finally:
        await db.close()


async def claim_next_runnable_task(*, worker_id: str, lease_seconds: int = 90) -> dict | None:
    """Claim a runnable queued task.

    This is a conservative implementation: it pulls a small batch of queued
    tasks and checks dependency completion in Python, then claims one inside an
    IMMEDIATE transaction to avoid double-claims.
    """
    now = utcnow_iso()

    db = await get_db()
    try:
        await db.execute("BEGIN IMMEDIATE")
        cur = await db.execute(
            "SELECT t.*, r.status AS run_status "
            "FROM tasks t JOIN runs r ON r.id = t.run_id "
            "WHERE t.status = 'queued' AND r.status IN ('queued','running') "
            "ORDER BY t.priority DESC, t.created_at ASC "
            "LIMIT 50"
        )
        candidates = await cur.fetchall()
        if not candidates:
            await db.commit()
            return None

        def deps_ready(run_id: str, deps: list[str], dep_status: dict[str, str]) -> tuple[bool, str | None]:
            if not deps:
                return True, None
            for dep in deps:
                st = dep_status.get(dep)
                if st is None:
                    return False, None
                if st in {"error", "cancelled"}:
                    return False, "dependency_failed"
                if st != "completed":
                    return False, None
            return True, None

        # Build status map per-run lazily.
        by_run: dict[str, dict[str, str]] = {}

        for row in candidates:
            d = dict(row)
            run_id = str(d.get("run_id") or "")
            task_id = str(d.get("task_id") or "")
            deps = json_loads(d.get("deps_json"), [])
            if run_id not in by_run:
                dep_cur = await db.execute("SELECT task_id, status FROM tasks WHERE run_id = ?", (run_id,))
                dep_rows = await dep_cur.fetchall()
                by_run[run_id] = {str(r["task_id"]): str(r["status"]) for r in dep_rows}
            ok, fail_reason = deps_ready(run_id, deps, by_run[run_id])
            if fail_reason:
                # Dependency failed -> cancel this task to avoid deadlock.
                await db.execute(
                    "UPDATE tasks SET status='cancelled', error=? WHERE run_id=? AND task_id=? AND status='queued'",
                    (fail_reason, run_id, task_id),
                )
                continue
            if not ok:
                continue

            # Claim it.
            # Use SQLite datetime arithmetic for lease_until.
            await db.execute(
                "UPDATE tasks SET status='running', worker_id=?, lease_until=datetime('now', ?), started_at=COALESCE(started_at, ?) "
                "WHERE run_id=? AND task_id=? AND status='queued'",
                (worker_id, f"+{max(5,int(lease_seconds))} seconds", now, run_id, task_id),
            )
            ch_cur = await db.execute("SELECT changes() AS n")
            ch_row = await ch_cur.fetchone()
            if not ch_row or int(ch_row["n"] or 0) != 1:
                continue

            # If run is still queued, mark as running and set started_at.
            await db.execute(
                "UPDATE runs SET status='running', started_at=COALESCE(started_at, ?) "
                "WHERE id=? AND status='queued'",
                (now, run_id),
            )

            await db.commit()
            claimed = dict(row)
            claimed["dependencies"] = deps
            claimed["spec"] = json_loads(claimed.get("spec_json"), {})
            return claimed

        await db.commit()
        return None
    except Exception:
        try:
            await db.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        await db.close()
