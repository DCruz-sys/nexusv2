# Nexus V2 Architecture

Multi-agent pentesting architecture with NIM-backed orchestration, memory, and guardrails.

## Repository layout contracts

The repository treats committed source and generated runtime outputs as separate concerns.

### Source-of-truth directories (tracked)

- `app/`, `nexus_v2/`, `agents/`, `tools/`: application code and runtime logic.
- `tests/`: test suites.
- `docs/`: design and operational documentation.
- `scripts/`: developer and CI utilities.
- `config/`, `schemas_v2/`, `database/`: declarative configuration and schemas.

### Runtime/output directories (must be ignored)

- `.runtime/data/`: sqlite runtime databases and lock sidecars.
- `.runtime/reports/`: generated scan, deadcode, and forensics report artifacts.

### Guardrails

- Do not commit generated report files.
- Do not commit sqlite runtime files (`*.db`, `*.db-shm`, `*.db-wal`).
- Use `python scripts/repo_sanity.py` in CI/local checks to prevent regressions.

### Legacy scaffold policy

After API unification, the deprecated top-level `api/` scaffold is removed.
All active API surfaces live in `app/routes/` (v1) and `nexus_v2/api/` (v2).
