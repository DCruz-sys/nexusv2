# NexusPenTest Unified Runtime

## Architecture
- Canonical runtime app: `app.main:app` only.
- API routes are under `app/routes/*` with compatibility endpoints for `/api/v1/pentest/*` in `app/routes/pentest_v3.py`.
- Agent orchestrator (`agents/orchestrator.py`) uses a unified V3 stack based on `core/self_learning_agent.py`.
- Tool execution is registry-driven via `tools/registry.py` + `tools/command_tool.py`; high-value wrappers remain handwritten.

## Startup
1. Install runtime deps: `pip install -r requirements.docker.txt`
2. Start API: `uvicorn app.main:app --host 0.0.0.0 --port 8000`
3. Health check: `curl http://127.0.0.1:8000/api/health`

## Supported Kali tools
High-value native wrappers: `nmap`, `nuclei`, `ffuf`, `sqlmap`, `amass`, `subfinder`, `httpx`.
All other Kali tools are loaded from registry metadata and executed by generic `CommandTool`.

## Tool onboarding
1. Add/update metadata in `kali_tools_dump.json` (or `app/frameworks/kali_tools.py` source catalog).
2. Ensure fields exist: name, category, risk/risk_level, command_template, parser_type, scope_policy.
3. Use `tools/factory.py:get_tool_wrapper()` to resolve either high-value wrappers or generic executor.
