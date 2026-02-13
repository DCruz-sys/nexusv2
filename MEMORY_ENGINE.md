# NexusPenTest Memory Engine

This project now includes a persistent memory layer that survives process restarts and new runs.

## What Is Persisted

- `memory_items`: semantic, episodic, procedural, and self-model memory
- `memory_checkpoints`: replayable state snapshots
- `memory_audit_log`: append-only write/retrieval audit trail
- `memory_edges`: relation links between memory nodes (graph-ready)

All are stored in `data/nexus.db`.

## Runtime Behavior

- Before each chat response, relevant memory is retrieved and injected into the system context.
- After each chat turn, durable facts are extracted and written asynchronously.
- After each scan step, scan findings/output are persisted as memory.
- Checkpoints are automatically saved for chat turns and scan status changes.
- Background maintenance periodically consolidates low-value history and prunes overflow.
- Users can explicitly teach memory in chat via `remember: <fact>`.
- If available, native accelerators are used:
  - Rust `memory_ranker` for fast retrieval scoring
  - Go `swarm_planner` for dependency-aware execution waves

## Memory APIs

- `GET /api/memory/session/{session_id}`: list memory items
- `GET /api/memory/search?session_id=...&q=...`: retrieve relevant memory context
- `POST /api/memory/teach/{session_id}`: explicitly teach the agent
- `POST /api/memory/checkpoint/{session_id}`: create checkpoint
- `GET /api/memory/checkpoints/{session_id}`: list checkpoints
- `GET /api/memory/checkpoint/{checkpoint_id}`: load checkpoint
- `POST /api/memory/consolidate/{session_id}`: run consolidation now
- `POST /api/memory/maintenance/run`: run maintenance cycle now
- `GET /api/memory/audit`: inspect memory audit events
- `GET /api/memory/stats`: memory utilization metrics
- `GET /api/memory/accelerators`: check native accelerator readiness

## Key Environment Settings

- `MEMORY_ENABLE_NIM_EXTRACTION=true|false`
- `MEMORY_EXTRACTION_MODEL=llama-3.1-8b`
- `MEMORY_RETRIEVAL_LIMIT=6`
- `MEMORY_CANDIDATE_LIMIT=250`
- `MEMORY_MIN_SCORE=0.35`
- `MEMORY_MAX_ITEMS=5000`
- `MEMORY_DECAY_DAYS=7`
- `MEMORY_AUTO_MAINTENANCE=true|false`
- `MEMORY_MAINTENANCE_INTERVAL_MIN=360`
- `MEMORY_WRITE_SECRET=<secret for write signatures>`
- `MEMORY_RANKER_BIN=bin/memory_ranker`
- `SWARM_PLANNER_BIN=bin/swarm_planner`
- `SWARM_MAX_PARALLEL=12`
- `SWARM_TASK_TIMEOUT_SEC=120`
- `SWARM_MAX_RETRIES=1`
- `ACCELERATOR_TIMEOUT_MS=1200`

## Build Native Accelerators

- Linux/macOS: `bash scripts/build_accelerators.sh`
- Windows (PowerShell): `powershell -ExecutionPolicy Bypass -File scripts/build_accelerators.ps1`

## Notes

- This design is intentionally local-first and works without external vector DB/graph services.
- If you later add Qdrant/Weaviate/Neo4j, keep this API surface and replace internals in `app/ai/memory_manager.py`.
