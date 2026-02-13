# Native Accelerators (Go + Rust)

This project supports optional native binaries to improve runtime performance:

- Rust: `memory_ranker` for memory candidate scoring.
- Go: `swarm_planner` for dependency-aware swarm task wave planning.

## Build

- Linux/macOS:
  - `bash scripts/build_accelerators.sh`
- Windows PowerShell:
  - `powershell -ExecutionPolicy Bypass -File scripts/build_accelerators.ps1`

Output binaries are placed in `bin/`.

## Runtime Configuration

Environment variables:

- `MEMORY_RANKER_BIN=bin/memory_ranker`
- `SWARM_PLANNER_BIN=bin/swarm_planner`
- `ACCELERATOR_TIMEOUT_MS=1200`

The Python app automatically falls back to pure-Python logic when these binaries are unavailable or return errors.

## Verify

- `GET /api/memory/accelerators`
