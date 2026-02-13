import asyncio
import hashlib
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseTool(ABC):
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

    async def _run_command(self, cmd: List[str], timeout: int = 300, use_docker: bool = True) -> Dict[str, Any]:
        final_cmd = cmd
        if use_docker:
            final_cmd = ["docker", "run", "--rm", "--network", "host", "kalilinux/kali-rolling", *cmd]
        try:
            process = await asyncio.create_subprocess_exec(*final_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            return {
                "stdout": stdout.decode(errors="ignore"),
                "stderr": stderr.decode(errors="ignore"),
                "exit_code": process.returncode,
                "success": process.returncode == 0,
            }
        except asyncio.TimeoutError:
            return {"error": f"timeout after {timeout}s", "success": False}

    def _generate_cache_key(self, cmd: List[str]) -> str:
        return hashlib.md5(" ".join(cmd).encode()).hexdigest()

    async def _get_cache(self, key: str) -> Optional[Dict[str, Any]]:
        return None

    async def _set_cache(self, key: str, value: Dict[str, Any]) -> None:
        return None
