# NexusPenTest Unified Runtime

## Architecture
- Canonical runtime app: `app.main:app` only.
- API routes are under `app/routes/*` with compatibility endpoints for `/api/v1/pentest/*` in `app/routes/pentest_v3.py`.
- Agent orchestrator (`agents/orchestrator.py`) uses a unified V3 stack based on `core/self_learning_agent.py`.
- Tool execution is registry-driven via `tools/registry.py` + `tools/command_tool.py`; high-value wrappers remain handwritten.

## Startup
1. Create and activate a virtual environment (recommended on Kali due to PEP 668):
   - `python -m venv .venv && source .venv/bin/activate`
2. Install core runtime deps: `pip install -r requirements.docker.txt`
3. (Optional) Install PostgreSQL/vector memory deps: `pip install -r requirements-postgres.txt`
4. Verify active interpreter and packages:
   - `python -c "import sys,shutil; print(sys.executable); print(shutil.which('uvicorn'))"`
   - `python -c "import litellm; print(litellm.__version__)"`
5. Start API (interpreter-safe): `python -m uvicorn app.main:app --host 0.0.0.0 --port 8000`
6. Health check: `curl http://127.0.0.1:8000/api/health`

### Kali note (PEP 668)
- If you see `externally-managed-environment`, use a virtualenv rather than system Python installs.
- For optional Postgres extras that compile native extensions, ensure build headers/tools are installed (`libpq-dev`, `python3-dev`, and `build-essential`) when needed.
- If traceback shows `/usr/bin/uvicorn`, reinstall dependencies inside the active venv and rerun with `python -m uvicorn app.main:app --host 0.0.0.0 --port 8000`.

## Supported Kali tools
- High-value native wrappers: `nmap`, `nuclei`, `ffuf`, `sqlmap`, `amass`, `subfinder`, `httpx`.
- Every other Kali tool in the registry is wrapped automatically through `CommandTool` via `tools.factory.get_all_tool_wrappers()`.
- Source catalog reference: https://www.kali.org/tools/all-tools/

## Tool onboarding
1. Add/update metadata in `kali_tools_dump.json` (or `app/frameworks/kali_tools.py` source catalog).
2. Ensure fields exist: `name`, `category`, `risk`/`risk_level`, `command_template`, `parser_type`, `scope_policy`.
3. `tools/registry.py` merges both sources into one normalized registry, and `tools/factory.py` resolves wrappers for every registry tool.
4. Run `pytest -q tests/test_tool_factory_wrappers.py` to verify high-value/native wrappers and full registry wrapper coverage.
