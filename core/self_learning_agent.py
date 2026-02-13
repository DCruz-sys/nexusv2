from __future__ import annotations

import hashlib
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
        target_profile = self._derive_target_profile(task)
        strategy_templates = await self._retrieve_strategy_templates(task, target_profile)

        self.current_experience = Experience(
            agent_name=self.name,
            task_type=task.get("type", "unknown"),
            task_description=task.get("description", ""),
            strategy={
                "exploration_rate": self.strategy_params["exploration_rate"],
                "retrieved_experiences": len(similar),
                "retrieved_templates": len(strategy_templates),
                "approach": "experience_based" if similar else "exploratory",
            },
            actions=[],
            observations=[],
            outcome=LearningSignal.FAILURE,
            reward=0.0,
        )

        result = await self._react_loop(task, similar, strategy_templates, context or {})

        self.current_experience.reward = self._calculate_reward(result)
        self.current_experience.outcome = LearningSignal.SUCCESS if result.get("success") else LearningSignal.FAILURE

        await self._store_experience()
        await self._distill_and_store_strategy_templates(task, target_profile)
        self._update_strategy_from_experience()
        return result

    async def _react_loop(
        self,
        task: Dict[str, Any],
        similar_experiences: List[Experience],
        strategy_templates: List[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        iterations = 0
        accumulated_context: Dict[str, Any] = {
            "task": task,
            "similar_experiences": [e.to_dict() for e in similar_experiences],
            "strategy_templates": strategy_templates,
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

    async def _retrieve_strategy_templates(self, task: Dict[str, Any], target_profile: str) -> List[Dict[str, Any]]:
        if not hasattr(self.memory, "query_procedural_memory"):
            return []
        try:
            rows = await self.memory.query_procedural_memory(
                agent_type=self.name,
                target_profile=target_profile,
                task_type=task.get("type", "unknown"),
                limit=3,
            )
        except Exception as exc:
            logger.warning(f"[{self.name}] could not retrieve procedural memory templates: {exc}")
            return []

        templates: List[Dict[str, Any]] = []
        for row in rows:
            template = row.get("strategy_template")
            if isinstance(template, str):
                try:
                    template = json.loads(template)
                except Exception:
                    template = {"raw": template}
            if isinstance(template, dict):
                template.setdefault("strategy_hash", row.get("strategy_hash"))
                template.setdefault("avg_reward", row.get("avg_reward"))
                template.setdefault("version", row.get("version"))
                templates.append(template)
        return templates

    async def _distill_and_store_strategy_templates(self, task: Dict[str, Any], target_profile: str) -> None:
        if not self.current_experience or not hasattr(self.memory, "store_procedural_memory"):
            return

        candidates = [
            e
            for e in self.experience_buffer[-25:]
            if e.task_type == self.current_experience.task_type and e.reward > 0 and e.actions
        ]
        if self.current_experience.reward > 0 and self.current_experience.actions and self.current_experience not in candidates:
            candidates.append(self.current_experience)
        if not candidates:
            return

        candidates.sort(key=lambda exp: exp.reward, reverse=True)
        top_candidates = candidates[:3]

        context_features = {
            "task_type": task.get("type", "unknown"),
            "target_profile": target_profile,
            "task_keywords": self._extract_task_keywords(task.get("description", "")),
        }

        for exp in top_candidates:
            sequence = self._build_action_sequence_template(exp.actions)
            template = {
                "name": f"{self.name}_{exp.task_type}_template",
                "task_type": exp.task_type,
                "summary": f"High-reward sequence for {exp.task_type}",
                "steps": sequence,
                "reward": exp.reward,
                "source": "self_distilled",
            }
            strategy_id = await self.memory.store_procedural_memory(
                agent_type=self.name,
                target_profile=target_profile,
                task_type=exp.task_type,
                strategy_template=template,
                context_features=context_features,
            )

            if hasattr(self.memory, "record_strategy_outcome"):
                strategy_hash = hashlib.sha256(json.dumps(template, sort_keys=True).encode()).hexdigest()
                await self.memory.record_strategy_outcome(
                    strategy_id=strategy_id,
                    strategy_hash=strategy_hash,
                    target_profile=target_profile,
                    task_type=exp.task_type,
                    reward=exp.reward,
                    outcome="success" if exp.outcome == LearningSignal.SUCCESS else "failure",
                    action_sequence=sequence,
                    context_features=context_features,
                )

        if hasattr(self.memory, "prune_procedural_memory"):
            await self.memory.prune_procedural_memory()

    @staticmethod
    def _build_action_sequence_template(actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        sequence: List[Dict[str, Any]] = []
        for idx, action in enumerate(actions):
            sequence.append(
                {
                    "step": idx + 1,
                    "action": action.get("action") or action.get("tool") or "unknown",
                    "goal": action.get("goal", ""),
                    "params": action.get("params", {}),
                }
            )
        return sequence

    @staticmethod
    def _extract_task_keywords(description: str) -> List[str]:
        tokens = [token.strip(" ,.:;!?\n\t").lower() for token in description.split()]
        return [token for token in tokens if token and len(token) > 3][:8]

    @staticmethod
    def _derive_target_profile(task: Dict[str, Any]) -> str:
        if task.get("target_profile"):
            return str(task["target_profile"])
        target = str(task.get("target", "unknown")).strip()
        if ":" in target:
            return target.split(":", 1)[0]
        return target

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
