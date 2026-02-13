#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================"
echo "  NexusPenTest - AI Penetration Testing"
echo "  Installation Script for Kali Linux"
echo "============================================"
echo ""

# Check Python version
PYTHON_CMD=""
if command -v python3.13 &>/dev/null; then
    PYTHON_CMD="python3.13"
elif command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
else
    echo "[ERROR] Python 3 is not installed. Please install Python 3.10+."
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD --version 2>&1)
echo "[+] Using $PYTHON_VERSION"

venv_is_valid() {
    local expected_command=" -m venv ${SCRIPT_DIR}/venv"
    [ -x "${SCRIPT_DIR}/venv/bin/python" ] || return 1
    [ -f "${SCRIPT_DIR}/venv/bin/activate" ] || return 1
    [ -f "${SCRIPT_DIR}/venv/pyvenv.cfg" ] || return 1
    grep -Fq "${expected_command}" "${SCRIPT_DIR}/venv/pyvenv.cfg" || return 1
}

ensure_venv() {
    if [ -d "${SCRIPT_DIR}/venv" ] && ! venv_is_valid; then
        echo "[!] Existing virtual environment is invalid for this workspace. Rebuilding..."
        rm -rf "${SCRIPT_DIR}/venv"
    fi

    if [ ! -d "${SCRIPT_DIR}/venv" ]; then
        echo "[+] Creating virtual environment..."
        "$PYTHON_CMD" -m venv "${SCRIPT_DIR}/venv"
    else
        echo "[+] Virtual environment is valid."
    fi
}

ensure_admin_username_env() {
    local env_file="${SCRIPT_DIR}/.env"
    if [ ! -f "${env_file}" ]; then
        return 0
    fi
    if grep -q '^AUTH_ADMIN_USERNAME=' "${env_file}"; then
        sed -i 's/^AUTH_ADMIN_USERNAME=.*/AUTH_ADMIN_USERNAME=admin/' "${env_file}"
    else
        printf '\nAUTH_ADMIN_USERNAME=admin\n' >> "${env_file}"
    fi
    echo "[+] Ensured AUTH_ADMIN_USERNAME=admin in .env"
}

normalize_env_blanks() {
    local env_file="${SCRIPT_DIR}/.env"
    if [ ! -f "${env_file}" ]; then
        return 0
    fi
    local normalized_json
    normalized_json="$("${SCRIPT_DIR}/venv/bin/python" -m app.system.env_normalizer --path "${env_file}")"
    export NEXUS_ENV_NORMALIZED_KEYS_JSON="${normalized_json}"
    echo "[+] Applied .env blank credential normalization policy: ${normalized_json}"
}

runtime_sanity_check() {
    echo "[+] Running runtime dependency sanity checks..."
    "${SCRIPT_DIR}/venv/bin/python" - <<'PY'
import importlib.util
import sys

required = ("prometheus_client", "uvicorn", "aiosqlite", "uvloop")
missing = [name for name in required if importlib.util.find_spec(name) is None]
if missing:
    print("[ERROR] Missing runtime modules: " + ", ".join(missing))
    sys.exit(1)
print("[+] Runtime dependency sanity checks passed.")
PY
}

ensure_venv

# Activate venv
source "${SCRIPT_DIR}/venv/bin/activate"

# Upgrade pip
echo "[+] Upgrading pip..."
pip install --upgrade pip --quiet

# Install dependencies
echo "[+] Installing Python dependencies..."
pip install -r requirements.txt --quiet

# Create .env file if not exists
if [ ! -f ".env" ]; then
    echo "[+] Creating .env configuration file..."
    cat > .env << 'ENVEOF'
NVIDIA_API_KEY=
NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1
HOST=127.0.0.1
PORT=8000
AUTH_ENABLED=true
AUTH_ADMIN_USERNAME=admin
AUTH_ADMIN_PASSWORD=change-me-admin-password
AUTH_BOOTSTRAP_API_KEY=change-me-bootstrap-key
AUTH_JWT_SECRET=change-me-in-production
DATABASE_PATH=data/nexus.db
REPORTS_DIR=reports
MEMORY_ENABLE_NIM_EXTRACTION=true
MEMORY_RETRIEVAL_LIMIT=6
MEMORY_CANDIDATE_LIMIT=250
MEMORY_MIN_SCORE=0.35
MEMORY_MAX_ITEMS=5000
MEMORY_DECAY_DAYS=7
MEMORY_AUTO_MAINTENANCE=true
MEMORY_MAINTENANCE_INTERVAL_MIN=360
MEMORY_WRITE_SECRET=
MEMORY_CHAT_SCOPE=global
CHAT_SESSION_PERSIST=true
MEMORY_RANKER_BIN=bin/memory_ranker
SWARM_PLANNER_BIN=bin/swarm_planner
SWARM_MAX_PARALLEL=4
SWARM_TASK_TIMEOUT_SEC=90
SWARM_MAX_RETRIES=1
SWARM_AUTONOMOUS_LEARNING_COOLDOWN_MIN=60
ACCELERATOR_TIMEOUT_MS=1200
MAX_CONCURRENT_TOOLS=2
RUNTIME_PROFILE=kali_8gb_balanced
NEMO_GUARDRAILS_ENABLED=true
NEMO_GUARDRAILS_CONFIG_PATH=app/ai/rails
NIM_STATELESS_METADATA=true
JOB_RUNNER_MODE=embedded
WORKER_HEARTBEAT_SEC=20
SCAN_WORKERS=1
CRAWLER_WORKERS=1
ANALYSIS_WORKERS=1
MAX_PENDING_SCANS=12
MAX_PENDING_CRAWL=8
MAX_PENDING_DISTILL=6
ENVEOF
    echo "[+] .env file created. Set NVIDIA_API_KEY and rotate AUTH_ADMIN_PASSWORD/AUTH_BOOTSTRAP_API_KEY before production use."
else
    echo "[+] .env file already exists, skipping."
fi
ensure_admin_username_env
normalize_env_blanks

# Create data directory
mkdir -p data reports

# Sanity-check required runtime modules
runtime_sanity_check

# Initialize database
echo "[+] Initializing database..."
"${SCRIPT_DIR}/venv/bin/python" -c "
import asyncio
import sys
sys.path.insert(0, '.')
from app.database import init_db
asyncio.run(init_db())
print('[+] Database initialized successfully.')
"

# Optional native accelerators (Rust + Go)
if command -v cargo &>/dev/null && command -v go &>/dev/null; then
    echo "[+] Building native accelerators (Rust + Go)..."
    bash scripts/build_accelerators.sh || echo "[!] Native accelerator build failed, using Python fallback."
else
    echo "[i] Rust/Go toolchains not found. Native accelerators skipped (Python fallback active)."
fi

echo ""
echo "============================================"
echo "  Installation Complete!"
echo "  Run: bash run.sh"
echo "============================================"
