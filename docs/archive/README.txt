NexusPenTest (Kali Lab Quick Start)

1) Requirements
- Kali Linux (recommended for runtime)
- Python 3.11+
- Optional: Go + Rust toolchains for native accelerators

2) Setup
- cp .env.example .env
- Edit .env and set at minimum:
  - NVIDIA_API_KEY
  - AUTH_ADMIN_PASSWORD
  - AUTH_BOOTSTRAP_API_KEY
  - AUTH_JWT_SECRET
- Run:
  - bash install.sh

3) Run
- bash run.sh
- API: http://127.0.0.1:8000
- Metrics: http://127.0.0.1:8000/metrics

4) Get Admin Token
- curl -X POST http://127.0.0.1:8000/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<AUTH_ADMIN_PASSWORD>"}'

5) Set Allowed Scope (required before scans)
- Add target rule (domain|ip|cidr):
  - POST /api/targets
- Example body:
  - {"type":"domain","pattern":"lab.local","created_by":"operator","enabled":true}

6) Start/Stop Scans
- Start: POST /scans
- Stop one: POST /scans/{scan_id}/stop
- Emergency stop all: POST /scans/stop-all

7) Start/Stop Swarm Runs (persistent multi-agent)
- Create: POST /api/swarm/runs
- List: GET /api/swarm/runs
- Inspect: GET /api/swarm/runs/{run_id}
- Stop: POST /api/swarm/runs/{run_id}/stop
- Live stream: GET /ws/swarm/{run_id} (WebSocket)

8) Safety and Ops
- Use only authorized lab targets.
- Keep crawler policy restrictive in isolated environments.
- Verify readiness before use:
  - GET /api/system/readiness
- Export forensic bundle for a run:
  - GET /api/system/forensics/{scan_id}

9) Optional Native Accelerators
- Build:
  - bash scripts/build_accelerators.sh
- Validate:
  - GET /api/memory/accelerators

Operator Safety Clause
- Use only for explicitly authorized security assessments in controlled lab scope.
- Any out-of-scope target or policy-violating action must be blocked and audited.
