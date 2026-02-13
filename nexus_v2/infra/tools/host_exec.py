"""Host-based tool execution adapter (v2).

Rules:
- argv only (no shell)
- binary must come from a tool recipe
- output is written to artifacts on disk; a short preview is returned
"""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import shutil
import signal
import time
from hashlib import sha256
from pathlib import Path
from typing import Awaitable, Callable

from nexus_v2.config import Settings, get_settings
from nexus_v2.core.usecases.redaction import redact_text
from nexus_v2.core.usecases.scope import parse_target
from nexus_v2.infra.repos.command_log import log_command_finish, log_command_start
from nexus_v2.infra.tools.registry_yaml import ToolRecipe


class ToolExecError(RuntimeError):
    pass


_BLOCKED_TOKENS = {";", "&&", "||", "|", "$(", ">", "<"}
_ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def _strip_ansi(value: str) -> str:
    return _ANSI_ESCAPE_RE.sub("", value or "")


def _validate_argv(argv: list[str]) -> None:
    for token in argv:
        if any(bad in token for bad in _BLOCKED_TOKENS):
            raise ToolExecError(f"blocked_token:{token}")


def _substitute(template: str, mapping: dict[str, str]) -> str:
    value = template
    for k, v in mapping.items():
        value = value.replace("{" + k + "}", v)
    return value


def build_argv(*, recipe: ToolRecipe, target: str, params: dict | None = None) -> list[str]:
    info = parse_target(target)
    p = params or {}
    mapping = {
        "binary": recipe.binary,
        "target": info.raw,
        "target_host": info.host,
        "target_url": info.url,
    }
    for k, v in p.items():
        mapping[str(k)] = str(v)

    argv = []
    for raw in recipe.args_template:
        rendered = _substitute(str(raw), mapping).strip()
        if not rendered:
            continue
        argv.append(rendered)
    if not argv:
        raise ToolExecError("empty_argv")

    # If args_template includes a single string with spaces, split it safely.
    if len(argv) == 1 and (" " in argv[0] or "\t" in argv[0]):
        argv = shlex.split(argv[0])

    _validate_argv(argv)
    return argv


async def run_tool(
    *,
    run_id: str,
    task_id: str,
    recipe: ToolRecipe,
    target: str,
    params: dict | None,
    timeout_sec: int,
    artifacts_dir: Path | None = None,
    on_stdout_line: Callable[[str], Awaitable[None]] | None = None,
    on_stderr_line: Callable[[str], Awaitable[None]] | None = None,
    should_stop: Callable[[], Awaitable[bool]] | None = None,
    settings: Settings | None = None,
) -> dict:
    settings = settings or get_settings()
    artifacts_root = (artifacts_dir or settings.artifacts_dir).resolve()
    task_dir = artifacts_root / run_id / task_id
    task_dir.mkdir(parents=True, exist_ok=True)

    argv = build_argv(recipe=recipe, target=target, params=params)
    binary = argv[0]
    resolved = shutil.which(binary)
    if not resolved:
        raise ToolExecError(f"tool_missing:{binary}")

    stdout_path = task_dir / "stdout.txt"
    stderr_path = task_dir / "stderr.txt"
    stdout_hash = sha256()
    stderr_hash = sha256()
    stdout_preview: list[str] = []
    stderr_preview: list[str] = []
    max_preview_bytes = int(settings.tool_inline_max_bytes)
    preview_bytes = 0

    cmd_log_id = await log_command_start(
        run_id=run_id,
        task_id=task_id,
        argv=argv,
        cwd=str(task_dir),
        env_redacted={},
    )

    start = time.perf_counter()
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(task_dir),
        start_new_session=True,
    )

    async def _kill_proc():
        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
            await asyncio.sleep(0.4)
            os.killpg(pgid, signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    async def _stop_watcher():
        if not should_stop:
            return
        while proc.returncode is None:
            try:
                if await should_stop():
                    await _kill_proc()
                    return
            except Exception:
                # Don't take down tool execution due to stop-check errors.
                pass
            await asyncio.sleep(0.8)

    async def _read_stream(stream, out_path: Path, digest, preview: list[str], cb, is_stderr: bool = False):
        nonlocal preview_bytes
        if stream is None:
            return
        with out_path.open("ab") as f:
            while True:
                chunk = await stream.readline()
                if not chunk:
                    break
                digest.update(chunk)
                f.write(chunk)
                # Preview + optional streaming events
                try:
                    decoded = chunk.decode("utf-8", errors="replace").rstrip("\n")
                except Exception:
                    decoded = repr(chunk)
                decoded = _strip_ansi(decoded)
                decoded = redact_text(decoded)
                if preview_bytes < max_preview_bytes:
                    preview.append(decoded)
                    preview_bytes += len(decoded.encode("utf-8", errors="replace")) + 1
                if cb is not None:
                    try:
                        await cb(decoded)
                    except Exception:
                        pass

    stop_task = asyncio.create_task(_stop_watcher())
    timed_out = False
    try:
        await asyncio.wait_for(
            asyncio.gather(
                proc.wait(),
                _read_stream(proc.stdout, stdout_path, stdout_hash, stdout_preview, on_stdout_line, False),
                _read_stream(proc.stderr, stderr_path, stderr_hash, stderr_preview, on_stderr_line, True),
            ),
            timeout=max(5, int(timeout_sec)),
        )
    except asyncio.TimeoutError:
        timed_out = True
        await _kill_proc()
        try:
            await asyncio.wait_for(proc.wait(), timeout=3.0)
        except Exception:
            pass
    finally:
        stop_task.cancel()
        try:
            await stop_task
        except BaseException:
            pass

    rc = proc.returncode
    duration = max(0.0, time.perf_counter() - start)
    await log_command_finish(command_log_id=cmd_log_id, rc=int(rc) if rc is not None else None)

    stdout_size = stdout_path.stat().st_size if stdout_path.exists() else 0
    stderr_size = stderr_path.stat().st_size if stderr_path.exists() else 0
    return {
        "argv": argv,
        "resolved_binary": resolved,
        "return_code": int(rc) if rc is not None else -1,
        "duration_sec": round(duration, 2),
        "timed_out": timed_out,
        "stdout": {
            "path": str(stdout_path),
            "sha256": stdout_hash.hexdigest(),
            "size_bytes": int(stdout_size),
            "preview": "\n".join(stdout_preview)[: max_preview_bytes],
        },
        "stderr": {
            "path": str(stderr_path),
            "sha256": stderr_hash.hexdigest(),
            "size_bytes": int(stderr_size),
            "preview": "\n".join(stderr_preview)[: max_preview_bytes],
        },
    }
