import json
from typing import Any, Dict

from tools.base_tool import BaseTool


class NucleiTool(BaseTool):
    def __init__(self):
        super().__init__("nuclei", "nuclei", "Template-based vulnerability scanner")

    async def execute(self, target: str, templates: str = "", additional_args: str = "") -> str:
        cmd = ["nuclei", "-u", target, "-jsonl"]
        if templates:
            cmd += ["-t", templates]
        if additional_args:
            cmd += additional_args.split()
        result = await self._run_command(cmd, timeout=900)
        return result.get("stdout", result.get("error", ""))

    def parse(self, output: str) -> Dict[str, Any]:
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return {"findings": findings, "count": len(findings)}
