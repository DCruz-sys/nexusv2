from typing import Dict

from tools.base_tool import BaseTool


class SubfinderTool(BaseTool):
    def __init__(self):
        super().__init__("subfinder", "subfinder", "Fast passive subdomain discovery")

    async def execute(self, target: str, additional_args: str = "") -> str:
        cmd = ["subfinder", "-d", target, "-silent"]
        if additional_args:
            cmd += additional_args.split()
        result = await self._run_command(cmd, timeout=600, target=target)
        return result.get("stdout", result.get("error", ""))

    def parse(self, output: str) -> Dict:
        subs = [line.strip() for line in output.splitlines() if line.strip()]
        return {"subdomains": subs, "count": len(subs)}
