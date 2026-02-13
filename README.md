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
- `pip install -r requirements.txt`
