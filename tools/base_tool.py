import asyncio
import hashlib
import os
import uuid
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from app.database import add_memory_audit_event
from app.security.allowlist import TargetNotAllowedError, parse_target, require_target_allowed


class BaseTool(ABC):
    DEFAULT_ALLOWED_TOOLS = {
        "nmap",
        "rustscan",
        "subfinder",
        "amass",
        "httpx",
        "nuclei",
    }
    DENIED_ARGUMENTS = {
        "--privileged",
        "--pid=host",
        "--cap-add=all",
        "--security-opt=seccomp=unconfined",
        "--network=host",
        "rm",
        "mkfs",
        "shutdown",
        "reboot",
    }
    MAX_TIMEOUT_SECONDS = 900
    DESTRUCTIVE_FLAGS = {"--flush-session", "--os-shell", "--force", "--delete", "--drop", "-rf"}

    def __init__(self, name: str, command: str, description: str):
        self.name = name
        self.command = command
        self.description = description
        self.cache_enabled = True

    @abstractmethod
    async def execute(self, **kwargs: Any) -> str:
        pass

    @abstractmethod
    def parse(self, output: str) -> Dict[str, Any]:
        pass

    async def normalize_and_validate_target(self, target: str) -> str:
        target_info = parse_target(target)
        if not target_info.normalized:
            raise TargetNotAllowedError("Target is required for tool execution.")
        await require_target_allowed(target_info.normalized, actor=f"tool:{self.name}", reason="tool_scope_check")
        return target_info.normalized

    def _allowed_tools(self) -> set[str]:
        raw_allowlist = os.getenv("TOOL_EXEC_ALLOWLIST", "")
        if not raw_allowlist.strip():
            return set(self.DEFAULT_ALLOWED_TOOLS)
        return {item.strip().lower() for item in raw_allowlist.split(",") if item.strip()}

    def _max_timeout(self) -> int:
        raw_timeout = os.getenv("TOOL_MAX_TIMEOUT_SEC", str(self.MAX_TIMEOUT_SECONDS)).strip()
        try:
            parsed = int(raw_timeout)
            return parsed if parsed > 0 else self.MAX_TIMEOUT_SECONDS
        except ValueError:
            return self.MAX_TIMEOUT_SECONDS

    def _has_denied_argument(self, cmd: List[str]) -> Optional[str]:
        for token in cmd:
            lowered = token.strip().lower()
            if not lowered:
                continue
            if lowered in self.DENIED_ARGUMENTS:
                return token
            if lowered.startswith("rm") and "-rf" in lowered:
                return token
        return None

    async def _policy_hook(self, cmd: List[str], timeout: int, target: Optional[str], approval_token: Optional[str]) -> Dict[str, Any]:
        allowed_tools = self._allowed_tools()
        if self.command.lower() not in allowed_tools:
            return {"allowed": False, "reason": f"tool_not_allowlisted:{self.command}"}

        if target is None or not str(target).strip():
            return {"allowed": False, "reason": "missing_target"}
        try:
            normalized_target = await self.normalize_and_validate_target(str(target))
        except TargetNotAllowedError as exc:
            return {"allowed": False, "reason": f"target_out_of_scope:{exc}"}

        denied_token = self._has_denied_argument(cmd)
        destructive = next((token for token in cmd if token.strip().lower() in self.DESTRUCTIVE_FLAGS), None)
        if (denied_token or destructive) and not approval_token:
            return {
                "allowed": False,
                "reason": f"denied_argument:{denied_token or destructive}",
            }

        max_timeout = self._max_timeout()
        if timeout > max_timeout:
            return {
                "allowed": False,
                "reason": f"timeout_exceeds_max:{timeout}>{max_timeout}",
            }

        return {
            "allowed": True,
            "normalized_target": normalized_target,
        }

    async def _run_command(
        self,
        cmd: List[str],
        timeout: int = 300,
        use_docker: bool = True,
        *,
        target: Optional[str] = None,
        approval_token: Optional[str] = None,
        retries: int = 0,
    ) -> Dict[str, Any]:
        correlation_id = str(uuid.uuid4())
        policy = await self._policy_hook(cmd=cmd, timeout=timeout, target=target, approval_token=approval_token)
        if not policy.get("allowed"):
            await add_memory_audit_event(
                event_type="tool_execution_policy_block",
                actor=f"tool:{self.name}",
                reason="pre_execution_policy",
                payload={
                    "correlation_id": correlation_id,
                    "tool": self.name,
                    "command": cmd,
                    "target": target,
                    "timeout": timeout,
                    "decision_reason": policy.get("reason"),
                    "policy_result": policy,
                },
            )
            return {"error": f"blocked_by_policy:{policy.get('reason', 'unknown')}", "success": False, "correlation_id": correlation_id}

        final_cmd = cmd
        if use_docker:
            final_cmd = ["docker", "run", "--rm", "--network", "host", "kalilinux/kali-rolling", *cmd]
        await add_memory_audit_event(
            event_type="tool_execution_started",
            actor=f"tool:{self.name}",
            reason="command_dispatch",
            payload={
                "correlation_id": correlation_id,
                "tool": self.name,
                "target": policy.get("normalized_target"),
                "command": cmd,
                "docker_command": final_cmd,
                "timeout": timeout,
                "retries": retries,
                "decision_reason": "policy_allow",
            },
        )

        max_attempts = max(1, retries + 1)
        for attempt in range(1, max_attempts + 1):
            try:
                process = await asyncio.create_subprocess_exec(*final_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                result = {
                    "stdout": stdout.decode(errors="ignore"),
                    "stderr": stderr.decode(errors="ignore"),
                    "exit_code": process.returncode,
                    "success": process.returncode == 0,
                    "attempt": attempt,
                    "correlation_id": correlation_id,
                }
                await add_memory_audit_event(
                    event_type="tool_execution_completed",
                    actor=f"tool:{self.name}",
                    reason="command_exit",
                    payload={
                        "correlation_id": correlation_id,
                        "tool": self.name,
                        "target": policy.get("normalized_target"),
                        "attempt": attempt,
                        "max_attempts": max_attempts,
                        "exit_code": process.returncode,
                        "success": result["success"],
                    },
                )
                if result["success"] or attempt >= max_attempts:
                    return result
            except asyncio.TimeoutError:
                await add_memory_audit_event(
                    event_type="tool_execution_timeout",
                    actor=f"tool:{self.name}",
                    reason="command_timeout",
                    payload={
                        "correlation_id": correlation_id,
                        "tool": self.name,
                        "target": policy.get("normalized_target"),
                        "attempt": attempt,
                        "max_attempts": max_attempts,
                        "timeout": timeout,
                    },
                )
                if attempt >= max_attempts:
                    return {"error": f"timeout after {timeout}s", "success": False, "attempt": attempt, "correlation_id": correlation_id}
        return {"error": "command_execution_failed", "success": False, "correlation_id": correlation_id}

    def _generate_cache_key(self, cmd: List[str]) -> str:
        return hashlib.md5(" ".join(cmd).encode()).hexdigest()

    async def _get_cache(self, key: str) -> Optional[Dict[str, Any]]:
        return None

    async def _set_cache(self, key: str, value: Dict[str, Any]) -> None:
        return None
