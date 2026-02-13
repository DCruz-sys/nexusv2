import json
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List

from loguru import logger


class BaseSecurityAgent(ABC):
    def __init__(self, name: str, role: str, nim_provider: Any, memory: Any, guardrails: Any):
        self.name = name
        self.role = role
        self.nim = nim_provider
        self.memory = memory
        self.guardrails = guardrails
        self.tools: List[Any] = []

    @abstractmethod
    async def reason(self, prompt: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def act(self, action_plan: Dict[str, Any]) -> Dict[str, Any]:
        pass

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        try:
            similar_cases = await self.memory.query_episodic(task.get("description", ""), self.name, 5)
            prompt = self._build_reasoning_prompt(task, similar_cases)
            plan = await self.reason(prompt)
            if not await self.guardrails.validate_action_plan(plan):
                return {"success": False, "error": "Action plan blocked by guardrails"}
            result = await self.act(plan)
            await self.memory.store_episodic(self.name, task, plan, result, result.get("success", False))
            return result
        except Exception as exc:
            logger.exception(exc)
            return {"success": False, "error": str(exc), "agent": self.name}

    def _build_reasoning_prompt(self, task: Dict[str, Any], similar_cases: List[Dict[str, Any]]) -> str:
        tools_text = "\n".join([f"- {tool.name}: {tool.description}" for tool in self.tools])
        return (
            f"You are {self.name}. Role: {self.role}\n"
            f"Task: {task.get('description','')}\nTarget: {task.get('target','unknown')}\n"
            f"Scope: {json.dumps(task.get('scope', {}))}\n"
            f"Similar cases count: {len(similar_cases)}\n"
            f"Available tools:\n{tools_text}\n"
            "Output strict JSON with keys reasoning, steps, risk_level, estimated_duration."
        )

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        cleaned = re.sub(r"^```json\s*|```$", "", response.strip(), flags=re.MULTILINE)
        return json.loads(cleaned)

    def _get_tool(self, tool_name: str) -> Any:
        for tool in self.tools:
            if tool.name.lower() == tool_name.lower():
                return tool
        return None

    def add_tool(self, tool: Any) -> None:
        self.tools.append(tool)
