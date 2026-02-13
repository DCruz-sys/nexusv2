import json
from typing import Any, Dict

from tools.base_tool import BaseTool


class FfufTool(BaseTool):
    def __init__(self):
        super().__init__("ffuf", "ffuf", "Fast web fuzzer")

    async def execute(self, url: str, wordlist: str, additional_args: str = "") -> str:
        cmd = ["ffuf", "-u", url, "-w", wordlist, "-of", "json"]
        if additional_args:
            cmd += additional_args.split()
        result = await self._run_command(cmd, timeout=900, target=url)
        return result.get("stdout", result.get("error", ""))

    def parse(self, output: str) -> Dict[str, Any]:
        data = json.loads(output) if output.strip() else {}
        return {"matches": data.get("results", []), "raw": data}
