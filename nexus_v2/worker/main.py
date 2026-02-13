"""Nexus v2 async worker.

Claims runnable tasks from SQLite and executes them.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path

from nexus_v2.config import get_settings
from nexus_v2.infra.db.sqlite import init_db
from nexus_v2.infra.repos.artifacts import add_artifact
from nexus_v2.infra.repos.artifacts import get_artifact
from nexus_v2.infra.repos.events import append_event
from nexus_v2.infra.repos.findings import create_finding, list_findings, update_finding, add_evidence
from nexus_v2.infra.repos.findings import get_finding
from nexus_v2.infra.repos.runs import get_run, get_run_status, update_run_status
from nexus_v2.infra.repos.tasks import claim_next_runnable_task, list_tasks, update_task_status, cancel_task, get_task
from nexus_v2.infra.repos.workers import upsert_worker_heartbeat
from nexus_v2.infra.tools.host_exec import ToolExecError, run_tool
from nexus_v2.infra.tools.registry_yaml import tool_registry


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _finalize_run_if_done(run_id: str) -> None:
    run = await get_run(run_id)
    if not run:
        return
    tasks = await list_tasks(run_id=run_id, limit=5000)
    if not tasks:
        return
    statuses = [str(t.get("status") or "") for t in tasks]
    if any(st == "running" for st in statuses) or any(st == "queued" for st in statuses):
        return

    # Any task error => run error.
    if any(st == "error" for st in statuses):
        await update_run_status(run_id=run_id, status="error", completed_at=_utcnow_iso(), error="task_failed")
        await append_event(run_id=run_id, event_type="run_error", payload={"run_id": run_id})
        return

    # Stopping => stopped, else completed.
    if str(run.get("status") or "") == "stopping":
        await update_run_status(run_id=run_id, status="stopped", completed_at=_utcnow_iso())
        await append_event(run_id=run_id, event_type="run_stopped", payload={"run_id": run_id})
    else:
        await update_run_status(run_id=run_id, status="completed", completed_at=_utcnow_iso())
        await append_event(run_id=run_id, event_type="run_completed", payload={"run_id": run_id})


async def _execute_tool_task(task: dict, *, worker_id: str) -> None:
    run_id = str(task.get("run_id") or "")
    task_id = str(task.get("task_id") or "")
    spec = task.get("spec") or {}
    tool_spec = spec.get("tool") or {}
    tool_name = str(tool_spec.get("name") or "").strip()
    tool_params = tool_spec.get("params") or {}

    run = await get_run(run_id)
    if not run:
        await update_task_status(run_id=run_id, task_id=task_id, status="error", error="run_not_found")
        return

    # Stop fast if run is stopping.
    if str(run.get("status") or "") == "stopping":
        await cancel_task(run_id=run_id, task_id=task_id, reason="run_stopping")
        return

    target_value = str((run.get("target") or {}).get("target") or "")
    if not target_value:
        await update_task_status(run_id=run_id, task_id=task_id, status="error", error="missing_target")
        return

    recipe = tool_registry.get(tool_name)
    if not recipe:
        await update_task_status(run_id=run_id, task_id=task_id, status="error", error=f"unknown_tool:{tool_name}")
        return

    await append_event(
        run_id=run_id,
        event_type="tool_start",
        payload={"run_id": run_id, "task_id": task_id, "tool": tool_name},
    )

    line_budget = 200
    sent = 0
    sent_err = 0

    async def on_stdout(line: str):
        nonlocal sent
        if sent < line_budget:
            await append_event(
                run_id=run_id,
                event_type="tool_output",
                payload={"run_id": run_id, "task_id": task_id, "stream": "stdout", "line": line[:2000]},
            )
        elif sent == line_budget:
            await append_event(
                run_id=run_id,
                event_type="tool_output_truncated",
                payload={"run_id": run_id, "task_id": task_id, "stream": "stdout", "limit": line_budget},
            )
        sent += 1

    async def on_stderr(line: str):
        nonlocal sent_err
        if sent_err < 80:
            await append_event(
                run_id=run_id,
                event_type="tool_output",
                payload={"run_id": run_id, "task_id": task_id, "stream": "stderr", "line": line[:2000]},
            )
        sent_err += 1

    async def should_stop() -> bool:
        status = await get_run_status(run_id)
        return str(status or "") in {"stopping", "stopped"}

    try:
        result = await run_tool(
            run_id=run_id,
            task_id=task_id,
            recipe=recipe,
            target=target_value,
            params=tool_params if isinstance(tool_params, dict) else {},
            timeout_sec=int(spec.get("timeout_sec") or recipe.timeout_sec_default),
            on_stdout_line=on_stdout,
            on_stderr_line=on_stderr,
            should_stop=should_stop,
        )
    except ToolExecError as exc:
        await update_task_status(run_id=run_id, task_id=task_id, status="error", error=str(exc))
        await append_event(
            run_id=run_id,
            event_type="tool_error",
            payload={"run_id": run_id, "task_id": task_id, "tool": tool_name, "error": str(exc)},
        )
        return
    except Exception as exc:
        await update_task_status(run_id=run_id, task_id=task_id, status="error", error=str(exc))
        await append_event(
            run_id=run_id,
            event_type="tool_error",
            payload={"run_id": run_id, "task_id": task_id, "tool": tool_name, "error": str(exc)},
        )
        return

    # Persist artifacts.
    stdout_art = await add_artifact(
        run_id=run_id,
        task_id=task_id,
        kind="stdout",
        path=str(result["stdout"]["path"]),
        sha256=str(result["stdout"]["sha256"]),
        size_bytes=int(result["stdout"]["size_bytes"]),
        meta={"tool": tool_name},
    )
    stderr_art = await add_artifact(
        run_id=run_id,
        task_id=task_id,
        kind="stderr",
        path=str(result["stderr"]["path"]),
        sha256=str(result["stderr"]["sha256"]),
        size_bytes=int(result["stderr"]["size_bytes"]),
        meta={"tool": tool_name},
    )

    rc = int(result.get("return_code") or -1)
    status = "completed" if rc == 0 and not bool(result.get("timed_out")) else "error"
    await update_task_status(
        run_id=run_id,
        task_id=task_id,
        status=status,
        completed_at=_utcnow_iso(),
        result={
            "tool": tool_name,
            "return_code": rc,
            "timed_out": bool(result.get("timed_out")),
            "duration_sec": float(result.get("duration_sec") or 0.0),
            "stdout_artifact_id": stdout_art["id"],
            "stderr_artifact_id": stderr_art["id"],
            "stdout_preview": result["stdout"]["preview"],
            "stderr_preview": result["stderr"]["preview"],
        },
    )
    await append_event(
        run_id=run_id,
        event_type="tool_finish",
        payload={
            "run_id": run_id,
            "task_id": task_id,
            "tool": tool_name,
            "return_code": rc,
            "timed_out": bool(result.get("timed_out")),
            "stdout_artifact_id": stdout_art["id"],
            "stderr_artifact_id": stderr_art["id"],
        },
    )


async def _execute_control_task(task: dict) -> None:
    run_id = str(task.get("run_id") or "")
    task_id = str(task.get("task_id") or "")
    spec = task.get("spec") or {}
    control = spec.get("control") or {}
    action = str(control.get("action") or "").strip().lower()
    params = control.get("params") or {}

    if action == "report_generate":
        await _control_generate_report(run_id=run_id, task_id=task_id)
        return
    if action == "validation_judge":
        await _control_validation_judge(run_id=run_id, task_id=task_id, params=params if isinstance(params, dict) else {})
        return

    await update_task_status(run_id=run_id, task_id=task_id, status="error", error=f"unknown_control:{action}")


async def _control_generate_report(*, run_id: str, task_id: str) -> None:
    run = await get_run(run_id)
    if not run:
        await update_task_status(run_id=run_id, task_id=task_id, status="error", error="run_not_found")
        return

    await append_event(run_id=run_id, event_type="report_start", payload={"run_id": run_id, "task_id": task_id})

    # Heuristic hypotheses: create if none exist yet.
    existing = await list_findings(run_id=run_id, limit=10)
    if not existing:
        tasks = await list_tasks(run_id=run_id, limit=5000)
        for t in tasks:
            if str(t.get("type")) != "tool":
                continue
            result = t.get("result_json")
            try:
                parsed = result and json.loads(result)
            except Exception:
                parsed = None
            preview = ""
            if isinstance(parsed, dict):
                preview = str(parsed.get("stdout_preview") or "") + "\n" + str(parsed.get("stderr_preview") or "")
            if "wordpress" in preview.lower():
                await create_finding(
                    run_id=run_id,
                    title="WordPress detected (hypothesis)",
                    category="technology",
                    severity="info",
                    state="hypothesis",
                    confidence=0.55,
                    summary="Technology fingerprint suggests WordPress. Validate via HTTP body evidence.",
                    meta={"must_contain_any": ["wp-content", "wordpress"]},
                )

    confirmed = [f for f in await list_findings(run_id=run_id, limit=5000) if f.get("state") == "confirmed"]
    rows = []
    for f in confirmed:
        rows.append(f"<li><b>{f.get('title')}</b> ({f.get('severity')})<br><pre>{(f.get('summary') or '')}</pre></li>")
    findings_html = "<ul>" + "\n".join(rows) + "</ul>" if rows else "<p>No confirmed findings.</p>"

    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Nexus v2 Report</title></head>
<body>
  <h1>Nexus v2 Report</h1>
  <h2>Run</h2>
  <pre>{run_id}</pre>
  <h2>Confirmed Findings</h2>
  {findings_html}
</body></html>
"""

    settings = get_settings()
    report_dir = Path(settings.artifacts_dir) / run_id / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "report.html"
    report_path.write_text(html, encoding="utf-8")

    import hashlib

    data = report_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    art = await add_artifact(
        run_id=run_id,
        task_id=task_id,
        kind="report_html",
        path=str(report_path),
        sha256=digest,
        size_bytes=len(data),
        meta={"format": "html"},
    )

    await update_task_status(
        run_id=run_id,
        task_id=task_id,
        status="completed",
        completed_at=_utcnow_iso(),
        result={"report_artifact_id": art["id"]},
    )
    await append_event(
        run_id=run_id,
        event_type="report_ready",
        payload={"run_id": run_id, "task_id": task_id, "report_artifact_id": art["id"]},
    )


async def _control_validation_judge(*, run_id: str, task_id: str, params: dict) -> None:
    finding_id = str(params.get("finding_id") or "").strip()
    artifact_id = str(params.get("artifact_id") or "").strip()
    source_task_id = str(params.get("source_task_id") or "").strip()
    if not finding_id:
        await update_task_status(run_id=run_id, task_id=task_id, status="error", error="missing_finding_id")
        return

    if not artifact_id and source_task_id:
        dep = await get_task(run_id=run_id, task_id=source_task_id)
        if dep:
            try:
                parsed = json.loads(dep.get("result_json") or "{}")
            except Exception:
                parsed = {}
            if isinstance(parsed, dict):
                artifact_id = str(parsed.get("stdout_artifact_id") or parsed.get("stderr_artifact_id") or "").strip()

    if not artifact_id:
        await update_task_status(run_id=run_id, task_id=task_id, status="error", error="missing_artifact_id")
        return

    finding = await get_finding(finding_id)
    if not finding:
        await update_task_status(run_id=run_id, task_id=task_id, status="error", error="finding_not_found")
        return

    art = await get_artifact(artifact_id)
    if not art:
        await update_task_status(run_id=run_id, task_id=task_id, status="error", error="artifact_not_found")
        return

    path = Path(str(art.get("path") or ""))
    content = ""
    try:
        # Only read a bounded amount for judging.
        content = path.read_text(encoding="utf-8", errors="replace")[:200_000]
    except Exception:
        content = ""

    meta = finding.get("meta") or {}
    must_any = meta.get("must_contain_any") if isinstance(meta, dict) else None
    ok = False
    if isinstance(must_any, list) and must_any:
        lowered = content.lower()
        ok = any(str(x).lower() in lowered for x in must_any)
    else:
        ok = bool(content.strip())

    if ok:
        await update_finding(finding_id=finding_id, state="confirmed", confidence=0.8)
        await add_evidence(finding_id=finding_id, kind="http_exchange", artifact_id=artifact_id, meta={"judge": "v2"})
        state = "confirmed"
    else:
        await update_finding(finding_id=finding_id, state="inconclusive", confidence=0.4)
        state = "inconclusive"

    await update_task_status(
        run_id=run_id,
        task_id=task_id,
        status="completed",
        completed_at=_utcnow_iso(),
        result={"finding_id": finding_id, "state": state},
    )
    await append_event(
        run_id=run_id,
        event_type="validation_judged",
        payload={"run_id": run_id, "task_id": task_id, "finding_id": finding_id, "state": state},
    )


async def _run_loop(*, worker_id: str) -> None:
    settings = get_settings()
    sem = asyncio.Semaphore(settings.max_parallel)

    async def runner(task: dict):
        async with sem:
            run_id = str(task.get("run_id") or "")
            task_id = str(task.get("task_id") or "")
            await append_event(run_id=run_id, event_type="task_start", payload={"run_id": run_id, "task_id": task_id})
            try:
                if str(task.get("type") or "") == "tool":
                    await _execute_tool_task(task, worker_id=worker_id)
                else:
                    await _execute_control_task(task)
            finally:
                await _finalize_run_if_done(run_id)

    in_flight: set[asyncio.Task] = set()
    while True:
        # Keep heartbeat fresh.
        await upsert_worker_heartbeat(
            worker_id=worker_id,
            role="worker",
            meta={"pid": os.getpid(), "host": socket.gethostname(), "updated_at": _utcnow_iso()},
        )

        # Clean finished tasks.
        done = {t for t in in_flight if t.done()}
        in_flight -= done

        # Claim when capacity available.
        if len(in_flight) >= settings.max_parallel:
            await asyncio.sleep(0.2)
            continue

        next_task = await claim_next_runnable_task(worker_id=worker_id, lease_seconds=120)
        if not next_task:
            await asyncio.sleep(0.6)
            continue

        in_flight.add(asyncio.create_task(runner(next_task)))


async def main() -> None:
    await init_db()
    tool_registry.load()
    worker_id = f"worker-{uuid.uuid4().hex[:10]}"
    await _run_loop(worker_id=worker_id)


if __name__ == "__main__":
    asyncio.run(main())
