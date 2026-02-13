# Nexus V2

Nexus V2 is a multi-agent penetration testing platform with NVIDIA NIM integration, semantic memory, and orchestrated workflows.

## Quick start

1. Configure `.env` from `.env.example`.
2. Start stack: `cd docker && docker compose up -d`
3. Initialize DB: `python ../database/init_db.py`
4. Start API: `uvicorn api.main:app --reload`
