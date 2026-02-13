from __future__ import annotations

import json
from typing import Any, Dict

from core.self_learning_agent import SelfLearningAgent
from tools.web.nuclei_tool import NucleiTool


class VulnScanAgent(SelfLearningAgent):
    def __init__(self, nim_provider: Any, memory_system: Any):
        super().__init__("VulnScanAgentV3", "Vulnerability scanning and detection specialist", nim_provider, memory_system)
        self.tool = NucleiTool()

    async def _reason(self, context: Dict[str, Any]) -> Dict[str, Any]:
        task = context.get("task", {})
        if context.get("history"):
            return {"is_complete": True, "reasoning": "Vulnerability pass complete."}
        prompt = f"Return JSON for nuclei scan params. Task={json.dumps(task)}"
        response = await self.nim.call_async(prompt=prompt, model_type="reasoning", response_format="json")
        thought = self._safe_json(response.get("content", ""), default={"tool": "nuclei", "params": {"target": task.get("target", "")}})
        thought.setdefault("is_complete", False)
        thought.setdefault("params", {})
        thought["params"].setdefault("target", task.get("target", ""))
        return thought

    async def _act(self, thought: Dict[str, Any]) -> Dict[str, Any]:
        out = await self.tool.execute(**thought.get("params", {}))
        return {"success": True, "raw_output": out}

    async def _observe(self, action: Dict[str, Any]) -> Dict[str, Any]:
        parsed = self.tool.parse(action.get("raw_output", ""))
        return {"success": True, "findings": parsed.get("findings", []), "parsed": parsed, "vulnerabilities": parsed.get("findings", [])}
