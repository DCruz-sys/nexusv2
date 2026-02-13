# Nexus V3 Self-Learning Foundation

This module introduces `core/self_learning_agent.py` with:

- ReACT loop (`_reason -> _act -> _observe`)
- Chain-of-Verification (`_verify`)
- Self-refinement on retry signals (`_refine_strategy`)
- Episodic experience storage and strategy updates
- Reward shaping (`success`, findings bonus, out-of-scope penalty)

## Integration notes

- Compatible with current `NVIDIANIMProvider` via `get_embedding`.
- Compatible with current `MemorySystem` `query_episodic(query_text, agent_type, limit)` and
  `store_episodic(agent_type, task, action_plan, results, success)` signatures.
- Also includes compatibility shims for future `embed()` or different memory signatures.

## Next steps

1. Derive specialized V3 agents (Recon/Vuln/Exploit) from `SelfLearningAgent`.
2. Add procedural memory table(s) for strategy patterns.
3. Add reinforcement metrics pipeline to telemetry (Langfuse/OTel).
