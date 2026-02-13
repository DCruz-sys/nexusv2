"""Safe Kali tool execution with streaming output and cancellation support."""
from __future__ import annotations

import asyncio
import os
import re
import shlex
import shutil
import signal
import time
from typing import Callable, Optional

from app.config import HITL_ENFORCE, TOOL_TIMEOUT
from app.database import add_memory_audit_event, get_command_policy, upsert_tool_capability
from app.frameworks.kali_tools import KALI_TOOL_NAMES, get_tool

# Strip terminal control codes from tool output so UI/report rendering stays clean.
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
ACTIVE_TOOL_PROCS: dict[int, dict] = {}
ACTIVE_TOOL_LOCK = asyncio.Lock()


def _strip_ansi(value: str) -> str:
    return ANSI_ESCAPE_RE.sub("", value or "")


# Allowlisted binaries only.
ALLOWED_TOOLS = KALI_TOOL_NAMES | {
    "curl",
    "wget",
    "nc",
    "netcat",
    "ping",
    "traceroute",
    "host",
    "nslookup",
    "arp",
    "iputils-arping",
    "ifconfig",
    "ip",
    "ss",
    "cat",
    "grep",
    "awk",
    "sed",
    "head",
    "tail",
    "wc",
    "sort",
    "uniq",
    "tee",
    "dig",
}

BLOCKED_PATTERNS = ["rm -rf /", "mkfs", "dd if=", "> /dev/"]
BLOCKED_TOKENS = [";", "&&", "||", "|", "$("]
HELP_ARGS = {"--help", "-h", "-hh", "/?"}
SAFE_TOOL_DEFAULTS = {
    "nmap": "-sV -sC --top-ports 100 -T4",
    "masscan": "--top-ports 100 --rate 1000",
    "nikto": "-h",
    "whatweb": "--log-verbose",
    "sslscan": "",
    "dnsenum": "",
    "gobuster": "dir -w /usr/share/wordlists/dirb/common.txt -q -t 20",
}


async def _register_active_proc(pid: int, scan_id: str | None, command: str, tool: str):
    try:
        pgid = os.getpgid(pid)
    except Exception:
        pgid = -1
    async with ACTIVE_TOOL_LOCK:
        ACTIVE_TOOL_PROCS[pid] = {
            "pgid": pgid,
            "scan_id": scan_id,
            "command": command[:500],
            "tool": tool,
            "started_at": time.time(),
        }


async def _unregister_active_proc(pid: int):
    async with ACTIVE_TOOL_LOCK:
        ACTIVE_TOOL_PROCS.pop(pid, None)


async def terminate_active_process_groups(scan_id: str | None = None) -> int:
    async with ACTIVE_TOOL_LOCK:
        rows = list(ACTIVE_TOOL_PROCS.items())
    pgids: set[int] = set()
    for _pid, meta in rows:
        if scan_id and str(meta.get("scan_id") or "") != str(scan_id):
            continue
        pgid = int(meta.get("pgid") or -1)
        if pgid > 0:
            pgids.add(pgid)
    for pgid in pgids:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except Exception:
            pass
    if pgids:
        await asyncio.sleep(0.4)
        for pgid in pgids:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except Exception:
                pass
    return len(pgids)


def _flag_match(token: str, pattern: str) -> bool:
    return token == pattern or token.startswith(f"{pattern}=")


def validate_command(command: str) -> tuple[bool, str]:
    """Validate command safety and scope."""
    if not command or not command.strip():
        return False, "empty command"

    lowered = command.lower()
    for pattern in BLOCKED_PATTERNS:
        if pattern in lowered:
            return False, f"blocked pattern detected: {pattern}"
    for token in BLOCKED_TOKENS:
        if token in command:
            return False, f"blocked shell token detected: {token}"

    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return False, f"invalid command syntax: {exc}"
    if not parts:
        return False, "could not parse command"

    binary = parts[0].split("/")[-1]
    if binary not in ALLOWED_TOOLS:
        return False, f"binary '{binary}' is outside the Kali allowlist"
    return True, "ok"


async def execute_tool(
    command: str,
    timeout: Optional[int] = None,
    on_output: Optional[Callable] = None,
    stop_event: Optional[asyncio.Event] = None,
    scan_id: str | None = None,
    hitl_approved: bool = False,
) -> dict:
    """Execute allowlisted tool command with streaming output."""
    timeout = timeout or TOOL_TIMEOUT
    is_valid, reason = validate_command(command)
    if not is_valid:
        return {
            "stdout": "",
            "stderr": f"command validation failed: {reason}",
            "return_code": -1,
            "duration": 0,
            "timed_out": False,
        }

    parts = shlex.split(command)
    binary_token = parts[0]
    binary = binary_token.split("/")[-1]
    path = shutil.which(binary_token) or shutil.which(binary)
    await upsert_tool_capability(
        tool_name=binary,
        available=bool(path),
        details={"path": path or "", "source": "runtime_check"},
    )
    if not path:
        return {
            "stdout": "",
            "stderr": f"required tool '{binary}' is not installed on this Kali host",
            "return_code": 127,
            "duration": 0,
            "timed_out": False,
        }

    policy = await get_command_policy(binary)
    if policy:
        blocked_args = [str(x).strip() for x in (policy.get("blocked_args") or []) if str(x).strip()]
        allowed_args = [str(x).strip() for x in (policy.get("allowed_args") or []) if str(x).strip()]

        for token in parts[1:]:
            if not token.startswith("-"):
                continue
            if any(_flag_match(token, blocked) for blocked in blocked_args):
                return {
                    "stdout": "",
                    "stderr": f"command policy violation: blocked argument '{token}'",
                    "return_code": -1,
                    "duration": 0,
                    "timed_out": False,
                }
        if allowed_args:
            for token in parts[1:]:
                if not token.startswith("-"):
                    continue
                if not any(_flag_match(token, allowed) for allowed in allowed_args):
                    return {
                        "stdout": "",
                        "stderr": f"command policy violation: argument '{token}' is not allowlisted",
                        "return_code": -1,
                        "duration": 0,
                        "timed_out": False,
                    }
        if bool(policy.get("hitl_required")) and HITL_ENFORCE and not hitl_approved:
            return {
                "stdout": "",
                "stderr": "command policy violation: HITL approval required for this tool",
                "return_code": -1,
                "duration": 0,
                "timed_out": False,
            }

    start_time = time.time()
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    timed_out = False
    await add_memory_audit_event(
        event_type="tool_exec_start",
        actor="executor",
        session_id=scan_id,
        reason="scan_tool_execution",
        payload={"scan_id": scan_id, "command": command[:500], "tool": binary},
    )

    try:
        proc = await asyncio.create_subprocess_exec(
            *parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=1024 * 1024,
            start_new_session=True,
        )
        await _register_active_proc(proc.pid, scan_id=scan_id, command=command, tool=binary)

        async def check_stop():
            from app.database import get_scan

            while True:
                if stop_event and stop_event.is_set():
                    break
                if scan_id:
                    try:
                        scan = await get_scan(scan_id)
                        if scan and scan.get("status") in ("stopping", "stopped"):
                            if stop_event:
                                stop_event.set()
                            break
                    except Exception:
                        pass
                try:
                    if stop_event:
                        await asyncio.wait_for(stop_event.wait(), timeout=2.0)
                        break
                    await asyncio.sleep(2.0)
                except asyncio.TimeoutError:
                    continue

            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGTERM)
                await asyncio.sleep(0.5)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass

        stop_task = asyncio.create_task(check_stop())

        async def read_stream(stream, collector, is_stderr: bool = False):
            while True:
                if stop_event and stop_event.is_set():
                    break
                try:
                    line = await asyncio.wait_for(stream.readline(), timeout=1.0)
                    if not line:
                        break
                    decoded = _strip_ansi(line.decode("utf-8", errors="replace").rstrip())
                    collector.append(decoded)
                    if on_output and not is_stderr:
                        try:
                            await on_output(decoded)
                        except Exception:
                            pass
                except asyncio.TimeoutError:
                    if proc.returncode is not None:
                        break
                    continue

        try:
            await asyncio.wait_for(
                asyncio.gather(
                    read_stream(proc.stdout, stdout_lines),
                    read_stream(proc.stderr, stderr_lines, True),
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            timed_out = True
            try:
                proc.terminate()
                await asyncio.sleep(2)
                proc.kill()
            except ProcessLookupError:
                pass

        stop_task.cancel()
        try:
            await stop_task
        except BaseException:
            pass

        await proc.wait()
        duration = time.time() - start_time
        return_code = proc.returncode if proc.returncode is not None else 0
        if stop_event and stop_event.is_set():
            return_code = -1
        result = {
            "stdout": _strip_ansi("\n".join(stdout_lines)),
            "stderr": _strip_ansi("\n".join(stderr_lines)),
            "return_code": return_code,
            "duration": round(duration, 2),
            "timed_out": timed_out,
        }
        await add_memory_audit_event(
            event_type="tool_exec_finish",
            actor="executor",
            session_id=scan_id,
            reason="scan_tool_execution",
            payload={
                "scan_id": scan_id,
                "command": command[:500],
                "tool": binary,
                "return_code": return_code,
                "timed_out": timed_out,
                "duration_sec": round(duration, 2),
            },
        )
        return result
    except Exception as exc:
        duration = time.time() - start_time
        await add_memory_audit_event(
            event_type="tool_exec_error",
            actor="executor",
            session_id=scan_id,
            reason="scan_tool_execution",
            payload={
                "scan_id": scan_id,
                "command": command[:500],
                "tool": binary,
                "error": str(exc),
            },
        )
        return {
            "stdout": _strip_ansi("\n".join(stdout_lines)),
            "stderr": _strip_ansi(str(exc)),
            "return_code": -1,
            "duration": round(duration, 2),
            "timed_out": False,
        }
    finally:
        try:
            if "proc" in locals() and getattr(proc, "pid", None):
                await _unregister_active_proc(proc.pid)
        except Exception:
            pass


def build_command(tool_name: str, target: str, args: str | None = None) -> str:
    """Build a command from tool template."""
    # Many Kali tools expect either a hostname/IP (e.g. nmap) or a URL (e.g. whatweb).
    # Normalizing here prevents malformed commands like `nmap ... http://example.com/`.
    from app.security.allowlist import parse_target

    raw_target = (target or "").strip()
    info = parse_target(raw_target)

    HOST_ONLY_TOOLS = {
        "nmap",
        "masscan",
        "hydra",
        "dig",
        "host",
        "dnsenum",
        "dnsrecon",
        "dnsmap",
        "fierce",
    }
    URL_TOOLS = {
        "whatweb",
        "nikto",
        "sqlmap",
        "wapiti",
    }

    normalized_target = raw_target
    if tool_name in HOST_ONLY_TOOLS:
        normalized_target = info.host
    elif tool_name in URL_TOOLS:
        if "://" in raw_target:
            normalized_target = raw_target
        else:
            normalized_target = f"http://{info.host}" if info.host else raw_target

    tool = get_tool(tool_name)
    if not tool:
        return f"{tool_name} {normalized_target}".strip()
    template = tool["command_template"]
    final_args = args if args is not None else str(tool.get("default_args", "")).strip()
    if final_args in HELP_ARGS:
        final_args = SAFE_TOOL_DEFAULTS.get(tool_name, "")
    cmd = template.replace("{target}", normalized_target).replace("{args}", final_args)
    return cmd.strip()
