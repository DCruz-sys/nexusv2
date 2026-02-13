from typing import Dict

from tools.base_tool import BaseTool


class HttpxTool(BaseTool):
    def __init__(self):
        super().__init__("httpx", "httpx", "HTTP probing")

    async def execute(self, target: str, additional_args: str = "") -> str:
        cmd = ["httpx", "-u", target, "-silent"]
        if additional_args:
            cmd += additional_args.split()
        result = await self._run_command(cmd, timeout=600, target=target)
        return result.get("stdout", result.get("error", ""))

    def parse(self, output: str) -> Dict:
        urls = [line.strip() for line in output.splitlines() if line.strip()]
        return {"urls": urls, "count": len(urls)}
