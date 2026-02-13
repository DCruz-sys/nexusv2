import re
from typing import Any, Dict

from tools.base_tool import BaseTool


class SqlmapTool(BaseTool):
    def __init__(self):
        super().__init__("sqlmap", "sqlmap", "Automated SQLi testing")

    async def execute(self, target: str, additional_args: str = "") -> str:
        cmd = ["sqlmap", "-u", target, "--batch"]
        if additional_args:
            cmd += additional_args.split()
        result = await self._run_command(cmd, timeout=1200)
        return result.get("stdout", result.get("error", ""))

    def parse(self, output: str) -> Dict[str, Any]:
        injections = re.findall(r"Parameter:\s*(.+?)\n", output)
        dbms = re.findall(r"back-end DBMS:\s*(.+)", output)
        return {"injectable_parameters": injections, "dbms": dbms[0] if dbms else None}
