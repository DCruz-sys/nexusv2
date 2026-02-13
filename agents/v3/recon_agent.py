from __future__ import annotations

import json
from typing import Any, Dict, List

from core.self_learning_agent import SelfLearningAgent
from tools.network.nmap_tool import NmapTool


class ReconAgent(SelfLearningAgent):
    """V3 recon agent using the SelfLearningAgent ReACT interface."""

    def __init__(self, nim_provider: Any, memory_system: Any):
        super().__init__(
            name="ReconAgentV3",
            role="Network reconnaissance and asset discovery specialist",
            nim_provider=nim_provider,
            memory_system=memory_system,
        )
        self.tools: List[Any] = [NmapTool()]

    async def _reason(self, context: Dict[str, Any]) -> Dict[str, Any]:
        task = context.get("task", {})
        history = context.get("history", [])
        if history:
            latest_observation = history[-1].get("observation", {})
            findings = latest_observation.get("findings", [])
            if findings:
                return {
                    "is_complete": True,
                    "reasoning": "Reconnaissance produced findings and can be finalized.",
                    "next_action": "summarize",
                    "expected_result": "Compiled findings",
                }

        prompt = f"""
You are ReconAgentV3. Build the next reconnaissance action as strict JSON.
TASK: {json.dumps(task)}
HISTORY_LENGTH: {len(history)}
Return keys: is_complete, is_impossible, reasoning, next_action, expected_result, tool, params.
"""
        response = await self.nim.call_async(prompt=prompt, model_type="reasoning", response_format="json")
        thought = self._safe_json(
            response.get("content", ""),
            default={
                "is_complete": False,
                "is_impossible": False,
                "reasoning": "Run baseline service scan.",
                "next_action": "nmap_scan",
                "expected_result": "Open ports and services",
                "tool": "nmap",
                "params": {
                    "target": task.get("target", ""),
                    "scan_type": "default",
                },
            },
        )

        thought.setdefault("is_complete", False)
        thought.setdefault("is_impossible", False)
        thought.setdefault("tool", "nmap")
        thought.setdefault("params", {})
        thought["params"].setdefault("target", task.get("target", ""))
        thought["params"].setdefault("scan_type", "default")
        return thought

    async def _act(self, thought: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = thought.get("tool", "nmap").lower()
        params = thought.get("params", {})

        selected = next((tool for tool in self.tools if tool.name.lower() == tool_name), None)
        if selected is None:
            return {"success": False, "tool": tool_name, "error": f"Tool {tool_name} not registered", "params": params}

        output = await selected.execute(**params)
        return {
            "success": True,
            "tool": selected.name,
            "params": params,
            "raw_output": output,
        }

    async def _observe(self, action: Dict[str, Any]) -> Dict[str, Any]:
        if not action.get("success"):
            return {"success": False, "findings": [], "error": action.get("error", "action failed")}

        selected = next((tool for tool in self.tools if tool.name.lower() == action.get("tool", "").lower()), None)
        if selected is None:
            return {"success": False, "findings": [], "error": f"Unknown tool {action.get('tool')}"}

        parsed = selected.parse(action.get("raw_output", ""))
        findings = [
            {
                "tool": selected.name,
                "open_ports": parsed.get("open_ports", []),
                "services": parsed.get("services", []),
                "os_detection": parsed.get("os_detection"),
                "vulnerabilities": parsed.get("vulnerabilities", []),
            }
        ]
        return {
            "success": True,
            "parsed": parsed,
            "findings": findings,
        }
