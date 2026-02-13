# Nexus v2 (Preview)

Nexus v2 is a recode-in-place (runs alongside the legacy `app/` service) that implements:

- Engagement-scoped allowlist (scope rules)
- Run/task graph execution model (SQLite)
- Append-only event stream (DB-backed; WS tails the DB so API/worker can be separate processes)
- YAML tool recipes (`catalog_v2/tools/*.yaml`)
- Host tool executor (argv-only, no shell) with artifact spill + paging
- Findings state machine + validation judge (confirmed findings only in report)
- Minimal UI at `/v2`

## Quick Start (Local)

1. Start the API:

```bash
bash run_v2.sh
```

2. Start the worker (separate terminal):

```bash
bash worker_v2.sh
```

3. Open UI:

- `http://127.0.0.1:8001/v2`

## API (v2)

- Health: `GET /api/v2/health`
- Engagements: `POST /api/v2/engagements`
- Scope rules: `POST /api/v2/engagements/{engagement_id}/scope-rules`
- Create run: `POST /api/v2/engagements/{engagement_id}/runs`
- Run detail: `GET /api/v2/runs/{run_id}`
- Events: `GET /api/v2/runs/{run_id}/events?since_seq=0`
- WS events: `GET /ws/v2/runs/{run_id}`
- Artifacts: `GET /api/v2/runs/{run_id}/artifacts/{artifact_id}?offset=0&limit=64000`
- Findings: `GET /api/v2/runs/{run_id}/findings`
- Validate finding: `POST /api/v2/findings/{finding_id}/validate`

## Notes

- DB path defaults to `.runtime/data/nexus_v2.db` (override with `NEXUS_V2_DATABASE_PATH`).
- Artifacts default to `artifacts_v2/` (override with `NEXUS_V2_ARTIFACTS_DIR`).

