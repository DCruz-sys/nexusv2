# Swarm Orchestration

The swarm engine now supports:

- Dependency-aware task graphs (`dependencies` per task)
- Priority-based scheduling
- Bounded parallel execution (`SWARM_MAX_PARALLEL`)
- Per-task timeout + retry (`SWARM_TASK_TIMEOUT_SEC`, `SWARM_MAX_RETRIES`)
- Optional Go-native wave planner (`go/swarm_planner`)
- Deterministic output ordering

Python entrypoint: `app/ai/agent_swarm.py`
