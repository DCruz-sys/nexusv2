# Nexus V2

Nexus V2 is a multi-agent penetration testing platform with NVIDIA NIM integration, semantic memory, and orchestrated workflows.

## Quick start

1. Configure `.env` from `.env.example` (includes a safe local default for `POSTGRES_PASSWORD`).
2. Start stack:
   - `cd docker && docker compose up -d`
3. Initialize DB schema:
   - `python ../database/init_db.py`
   - The script first tries `asyncpg`; if unavailable, it automatically falls back to `docker compose exec postgres psql`.
4. Start API:
   - `uvicorn api.main:app --reload`

## Kali/Python note

Kali enforces PEP 668 for system Python. Prefer a virtual environment for local tooling:

- `python3 -m venv .venv`
- `source .venv/bin/activate`
- `pip install -r requirements.txt` (dev profile)


## Dependency profiles

Dependencies are split by profile:

- `requirements-runtime.in` / `requirements-runtime.txt`: production runtime dependencies.
- `requirements-dev.in` / `requirements-dev.txt`: runtime + development tooling.
- `requirements-research.in` / `requirements-research.txt`: optional heavy frameworks and research tooling.
- `requirements.docker.txt`: container install target (runtime-only, pinned lockfile).

Heavy optional frameworks (for example `crewai` and `langchain*` integrations) are intentionally kept out of runtime and only included in the research profile.

To refresh lockfiles:

- `uv pip compile requirements-runtime.in -o requirements-runtime.txt`
- `uv pip compile requirements-dev.in -o requirements-dev.txt`
- `uv pip compile requirements-research.in -o requirements-research.txt`
