import asyncio

import pytest

from core.self_learning_agent import LearningSignal, SelfLearningAgent


class DummyNIM:
    async def call_async(self, **kwargs):
        return {"content": '{"is_valid": true, "confidence": 0.9, "decision": "continue"}'}

    async def get_embedding(self, text: str):
        return [0.1, 0.2, 0.3]


class DummyMemory:
    def __init__(self):
        self.stored = []
        self.procedural_stored = []
        self.outcomes = []
        self.pruned = False

    async def query_episodic(self, query_text, agent_type=None, limit=5):
        return []

    async def store_episodic(self, **kwargs):
        self.stored.append(kwargs)

    async def query_procedural_memory(self, agent_type, target_profile, task_type, limit=3):
        return [{"strategy_template": {"name": "known_template", "steps": [{"action": "scan"}]}, "avg_reward": 1.2, "version": 1}]

    async def store_procedural_memory(self, **kwargs):
        self.procedural_stored.append(kwargs)
        return len(self.procedural_stored)

    async def record_strategy_outcome(self, **kwargs):
        self.outcomes.append(kwargs)

    async def prune_procedural_memory(self):
        self.pruned = True


class MinimalAgent(SelfLearningAgent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.last_reason_context = None
        self._reason_calls = 0

    async def _reason(self, context):
        self.last_reason_context = context
        self._reason_calls += 1
        if self._reason_calls == 1:
            return {"is_complete": False, "reasoning": "collect data", "next_action": "scan"}
        return {"is_complete": True, "reasoning": "done"}

    async def _act(self, thought):
        return {"action": "noop"}

    async def _observe(self, action):
        return {"findings": [{"service": "https"}]}


class RetryAgent(SelfLearningAgent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._step = 0

    async def _reason(self, context):
        self._step += 1
        if self._step >= 2:
            return {"is_complete": True, "reasoning": "completed after retry"}
        return {"next_action": "probe", "expected_result": "ok"}

    async def _act(self, thought):
        return {"action": "probe"}

    async def _observe(self, action):
        return {"findings": []}

    async def _verify(self, observation, expected_thought):
        if self._step == 1:
            return {"is_valid": False, "decision": "retry"}
        return {"is_valid": True, "decision": "continue"}



def test_learn_and_execute_stores_experience_and_updates_strategy():
    agent = MinimalAgent("Meta", "test", DummyNIM(), DummyMemory(), learning_rate=0.1)
    before = agent.strategy_params["exploration_rate"]
    result = asyncio.run(agent.learn_and_execute({"type": "recon", "description": "test target", "task_id": "task-1"}))

    assert result["success"] is True
    assert agent.current_experience is not None
    assert agent.current_experience.outcome == LearningSignal.SUCCESS
    assert agent.strategy_params["exploration_rate"] < before
    assert len(agent.experience_buffer) == 1
    assert result["telemetry"]["task_id"] == "task-1"
    assert "Meta" in result["telemetry"]["agents"]



def test_reward_penalizes_out_of_scope_and_rewards_findings():
    agent = MinimalAgent("Meta", "test", DummyNIM(), DummyMemory(), learning_rate=0.1)
    reward = agent._calculate_reward({"success": True, "findings": [1, 2, 3], "out_of_scope_actions": 1})
    assert reward == pytest.approx(1.1)



def test_react_loop_records_retry_counters():
    agent = RetryAgent("Retry", "test", DummyNIM(), DummyMemory(), learning_rate=0.1)
    result = asyncio.run(agent.learn_and_execute({"type": "scan", "description": "needs retry", "task_id": "task-retry"}))

    row = result["telemetry"]["agents"]["Retry"]
    assert row["thought_count"] >= 2
    assert row["action_count"] >= 1
    assert row["verification_count"] >= 1
    assert row["retry_count"] >= 1
