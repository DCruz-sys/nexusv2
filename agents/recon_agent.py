from typing import Any, Dict

from agents.base_agent import BaseSecurityAgent
from loguru import logger
from tools.network.nmap_tool import NmapTool


class ReconAgent(BaseSecurityAgent):
    def __init__(self, nim_provider: Any, memory: Any, guardrails: Any):
        super().__init__("ReconAgent", "Network reconnaissance and asset discovery specialist", nim_provider, memory, guardrails)
        self.add_tool(NmapTool())

    async def reason(self, prompt: str) -> Dict[str, Any]:
        response = await self.nim.call_async(prompt=prompt, model_type="reasoning", response_format="json")
        return self._parse_json_response(response["content"])

    async def act(self, action_plan: Dict[str, Any]) -> Dict[str, Any]:
        results = {"agent": self.name, "findings": [], "success": True, "discovered_assets": [], "open_ports": [], "services": []}
        for step in action_plan.get("steps", []):
            tool = self._get_tool(step.get("tool", ""))
            if not tool:
                continue
            try:
                output = await tool.execute(**step.get("params", {}))
                parsed = tool.parse(output)
                results["findings"].append({"tool": tool.name, "parsed": parsed})
                results["open_ports"].extend(parsed.get("open_ports", []))
                results["services"].extend(parsed.get("services", []))
            except Exception as exc:
                logger.error(exc)
                results["success"] = False
        results["total_ports"] = len(results["open_ports"])
        return results
