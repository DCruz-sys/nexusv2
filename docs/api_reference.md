# API Reference

## Canonical runtime (app.main)

- `POST /api/pentest/v3/start`
- `GET /api/pentest/v3/status/{task_id}`
- `GET /api/health`

## Compatibility endpoints (deprecated)

- `POST /api/v1/pentest/start` -> proxies to `/api/pentest/v3/start`
- `GET /api/v1/pentest/status/{task_id}` -> proxies to `/api/pentest/v3/status/{task_id}`
- `GET /health` -> proxies to `/api/health`
