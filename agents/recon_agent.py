from __future__ import annotations

import json
from typing import Any, Dict

from core.self_learning_agent import SelfLearningAgent
from tools.network.nmap_tool import NmapTool


class ReconAgent(SelfLearningAgent):
    def __init__(self, nim_provider: Any, memory_system: Any):
        super().__init__("ReconAgentV3", "Network reconnaissance and asset discovery specialist", nim_provider, memory_system)
        self.tool = NmapTool()

    async def _reason(self, context: Dict[str, Any]) -> Dict[str, Any]:
        task = context.get("task", {})
        if context.get("history"):
            return {"is_complete": True, "reasoning": "Recon loop complete."}
        prompt = f"Return JSON with tool params for nmap. Task={json.dumps(task)}"
        response = await self.nim.call_async(prompt=prompt, model_type="reasoning", response_format="json")
        thought = self._safe_json(response.get("content", ""), default={"tool": "nmap", "params": {"target": task.get("target", ""), "scan_type": "default"}})
        thought.setdefault("is_complete", False)
        thought.setdefault("tool", "nmap")
        thought.setdefault("params", {})
        thought["params"].setdefault("target", task.get("target", ""))
        return thought

    async def _act(self, thought: Dict[str, Any]) -> Dict[str, Any]:
        output = await self.tool.execute(**thought.get("params", {}))
        return {"success": True, "tool": "nmap", "raw_output": output}

    async def _observe(self, action: Dict[str, Any]) -> Dict[str, Any]:
        parsed = self.tool.parse(action.get("raw_output", ""))
        return {"success": True, "findings": [{"tool": "nmap", **parsed}], "parsed": parsed}
