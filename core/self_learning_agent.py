from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    from loguru import logger
except Exception:  # pragma: no cover
    import logging

    logger = logging.getLogger(__name__)


class LearningSignal(Enum):
    """Learning outcomes used for reinforcement updates."""

    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    NOVEL = "novel"
    VERIFICATION = "verification"
    REFINEMENT = "refinement"


@dataclass
class Experience:
    """Single episodic record produced by an agent run."""

    agent_name: str
    task_type: str
    task_description: str
    strategy: Dict[str, Any]
    actions: List[Dict[str, Any]]
    observations: List[Dict[str, Any]]
    outcome: LearningSignal
    reward: float
    timestamp: datetime = field(default_factory=datetime.now)
    embedding: Optional[List[float]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "task_type": self.task_type,
            "task_description": self.task_description,
            "strategy": self.strategy,
            "actions": self.actions,
            "observations": self.observations,
            "outcome": self.outcome.value,
            "reward": self.reward,
            "timestamp": self.timestamp.isoformat(),
            "embedding": self.embedding,
        }


class SelfLearningAgent(ABC):
    """ReACT + verification + self-refinement base class for Nexus V3 agents."""

    def __init__(
        self,
        name: str,
        role: str,
        nim_provider: Any,
        memory_system: Any,
        learning_rate: float = 0.1,
    ) -> None:
        self.name = name
        self.role = role
        self.nim = nim_provider
        self.memory = memory_system
        self.learning_rate = learning_rate

        self.current_experience: Optional[Experience] = None
        self.experience_buffer: List[Experience] = []

        self.max_iterations = 15
        self.strategy_params: Dict[str, Any] = {
            "exploration_rate": 0.3,
            "tool_timeout": 300,
            "retry_attempts": 3,
            "confidence_threshold": 0.7,
        }

    async def learn_and_execute(self, task: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        similar = await self._retrieve_similar_experiences(task)

        self.current_experience = Experience(
            agent_name=self.name,
            task_type=task.get("type", "unknown"),
            task_description=task.get("description", ""),
            strategy={
                "exploration_rate": self.strategy_params["exploration_rate"],
                "retrieved_experiences": len(similar),
                "approach": "experience_based" if similar else "exploratory",
            },
            actions=[],
            observations=[],
            outcome=LearningSignal.FAILURE,
            reward=0.0,
        )

        result = await self._react_loop(task, similar, context or {})

        self.current_experience.reward = self._calculate_reward(result)
        self.current_experience.outcome = LearningSignal.SUCCESS if result.get("success") else LearningSignal.FAILURE

        await self._store_experience()
        self._update_strategy_from_experience()
        return result

    async def _react_loop(
        self,
        task: Dict[str, Any],
        similar_experiences: List[Experience],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        iterations = 0
        accumulated_context: Dict[str, Any] = {
            "task": task,
            "similar_experiences": [e.to_dict() for e in similar_experiences],
            "history": [],
            "findings": [],
            **context,
        }

        while iterations < self.max_iterations:
            thought = await self._reason(accumulated_context)

            if thought.get("is_complete", False):
                return await self._finalize_success(accumulated_context, thought)

            if thought.get("is_impossible", False):
                return await self._finalize_failure(accumulated_context, thought.get("reason", "Task deemed impossible"))

            action = await self._act(thought)
            self.current_experience.actions.append(action)

            observation = await self._observe(action)
            self.current_experience.observations.append(observation)

            verification = await self._verify(observation, thought)

            accumulated_context["history"].append(
                {
                    "iteration": iterations,
                    "thought": thought,
                    "action": action,
                    "observation": observation,
                    "verification": verification,
                }
            )

            if verification.get("is_valid", True):
                accumulated_context["findings"].extend(self._extract_findings(observation))
            elif verification.get("decision") == "retry":
                refinement = await self._refine_strategy(action, observation)
                accumulated_context.setdefault("refinements", []).append(refinement)

            iterations += 1

        return await self._finalize_failure(accumulated_context, "Maximum iterations reached without completion")

    @abstractmethod
    async def _reason(self, context: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def _act(self, thought: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def _observe(self, action: Dict[str, Any]) -> Dict[str, Any]:
        pass

    async def _verify(self, observation: Dict[str, Any], expected_thought: Dict[str, Any]) -> Dict[str, Any]:
        verification_prompt = f"""
Verify this observation against expected outcome.
EXPECTED ACTION: {expected_thought.get('next_action', 'unknown')}
EXPECTED RESULT: {expected_thought.get('expected_result', 'unknown')}
OBSERVATION:
{json.dumps(observation, indent=2)}
Return JSON with keys: is_valid, confidence, decision, notes.
"""
        try:
            response = await self.nim.call_async(prompt=verification_prompt, model_type="reasoning", temperature=0.1)
            return self._safe_json(response.get("content", ""), default={"is_valid": True, "confidence": 0.5, "decision": "continue"})
        except Exception as exc:
            logger.warning(f"[{self.name}] verification fallback due to error: {exc}")
            return {"is_valid": True, "confidence": 0.5, "decision": "continue", "notes": "verification fallback"}

    async def _refine_strategy(self, failed_action: Dict[str, Any], observation: Dict[str, Any]) -> Dict[str, Any]:
        prompt = f"""
Analyze failed action and suggest improved strategy.
FAILED ACTION:
{json.dumps(failed_action, indent=2)}
OBSERVATION:
{json.dumps(observation, indent=2)}
Return JSON with analysis, improved_strategy, alternative_tools.
"""
        try:
            response = await self.nim.call_async(prompt=prompt, model_type="reasoning", temperature=0.3)
            return self._safe_json(response.get("content", ""), default={"analysis": "unavailable", "improved_strategy": {}, "alternative_tools": []})
        except Exception as exc:
            logger.warning(f"[{self.name}] strategy refinement fallback due to error: {exc}")
            return {"analysis": "refinement unavailable", "improved_strategy": {}, "alternative_tools": []}

    async def _retrieve_similar_experiences(self, task: Dict[str, Any]) -> List[Experience]:
        task_text = task.get("description", "")
        embedding = await self._embed_text(task_text)

        # Compatibility path for current MemorySystem (query_text + agent_type)
        if hasattr(self.memory, "query_episodic"):
            try:
                rows = await self.memory.query_episodic(query_text=task_text, agent_type=self.name, limit=5)
            except TypeError:
                # Compatibility path for a future signature (task_type + embedding)
                rows = await self.memory.query_episodic(task_type=task.get("type", "unknown"), embedding=embedding, limit=5)
        else:
            rows = []

        experiences: List[Experience] = []
        for row in rows or []:
            experiences.append(
                Experience(
                    agent_name=row.get("agent_type", self.name),
                    task_type=task.get("type", "unknown"),
                    task_description=task_text,
                    strategy={"source": "memory"},
                    actions=[],
                    observations=[],
                    outcome=LearningSignal.SUCCESS if row.get("success") else LearningSignal.FAILURE,
                    reward=0.0,
                    embedding=embedding,
                )
            )
        return experiences

    async def _store_experience(self) -> None:
        if not self.current_experience:
            return

        text = (
            f"{self.current_experience.task_description} "
            f"Strategy: {self.current_experience.strategy} "
            f"Outcome: {self.current_experience.outcome.value}"
        )
        self.current_experience.embedding = await self._embed_text(text)

        if hasattr(self.memory, "store_episodic"):
            try:
                await self.memory.store_episodic(
                    agent_type=self.name,
                    task={"description": self.current_experience.task_description},
                    action_plan={"steps": self.current_experience.actions},
                    results={
                        "observations": self.current_experience.observations,
                        "reward": self.current_experience.reward,
                        "learning_signal": self.current_experience.outcome.value,
                    },
                    success=self.current_experience.outcome == LearningSignal.SUCCESS,
                )
            except TypeError:
                await self.memory.store_episodic(self.current_experience)

        self.experience_buffer.append(self.current_experience)

    def _update_strategy_from_experience(self) -> None:
        if not self.current_experience:
            return

        current = self.strategy_params["exploration_rate"]
        if self.current_experience.outcome == LearningSignal.SUCCESS:
            current *= 1 - self.learning_rate
        else:
            current = min(0.9, current + self.learning_rate)

        self.strategy_params["exploration_rate"] = max(0.1, min(0.9, current))

    def _calculate_reward(self, result: Dict[str, Any]) -> float:
        reward = 1.0 if result.get("success") else -0.5
        reward += 0.1 * len(result.get("findings", []))
        reward -= 0.2 * result.get("out_of_scope_actions", 0)
        return reward

    async def _finalize_success(self, context: Dict[str, Any], thought: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "agent": self.name,
            "reasoning_summary": thought.get("reasoning", "Task completed"),
            "findings": context.get("findings", []),
            "iterations": len(context.get("history", [])),
            "history": context.get("history", []),
        }

    async def _finalize_failure(self, context: Dict[str, Any], reason: str) -> Dict[str, Any]:
        return {
            "success": False,
            "agent": self.name,
            "error": reason,
            "findings": context.get("findings", []),
            "iterations": len(context.get("history", [])),
            "history": context.get("history", []),
        }

    def _extract_findings(self, observation: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = observation.get("findings")
        if isinstance(findings, list):
            return findings
        if findings:
            return [{"value": findings}]
        return []

    async def _embed_text(self, text: str) -> List[float]:
        if hasattr(self.nim, "get_embedding"):
            return await self.nim.get_embedding(text)
        if hasattr(self.nim, "embed"):
            return await self.nim.embed(text)
        raise AttributeError("NIM provider does not expose get_embedding/embed")

    @staticmethod
    def _safe_json(raw: str, default: Dict[str, Any]) -> Dict[str, Any]:
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.startswith("json"):
                cleaned = cleaned[4:].strip()
        try:
            parsed = json.loads(cleaned)
            return parsed if isinstance(parsed, dict) else default
        except Exception:
            return default
