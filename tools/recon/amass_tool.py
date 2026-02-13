from typing import Dict

from tools.base_tool import BaseTool


class AmassTool(BaseTool):
    def __init__(self):
        super().__init__("amass", "amass", "Subdomain enumeration")

    async def execute(self, target: str, additional_args: str = "") -> str:
        cmd = ["amass", "enum", "-d", target]
        if additional_args:
            cmd += additional_args.split()
        result = await self._run_command(cmd, timeout=900, target=target)
        return result.get("stdout", result.get("error", ""))

    def parse(self, output: str) -> Dict:
        subs = [line.strip() for line in output.splitlines() if line.strip()]
        return {"subdomains": subs, "count": len(subs)}
