#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

venv_is_valid() {
    local expected_command=" -m venv ${SCRIPT_DIR}/venv"
    [ -x "${SCRIPT_DIR}/venv/bin/python" ] || return 1
    [ -f "${SCRIPT_DIR}/venv/bin/activate" ] || return 1
    [ -f "${SCRIPT_DIR}/venv/pyvenv.cfg" ] || return 1
    grep -Fq "${expected_command}" "${SCRIPT_DIR}/venv/pyvenv.cfg" || return 1
}

ensure_runtime_venv() {
    if venv_is_valid; then
        echo "[+] Virtual environment is valid."
        return 0
    fi

    if [ -d "${SCRIPT_DIR}/venv" ]; then
        echo "[!] Existing virtual environment is invalid for this workspace."
    else
        echo "[!] Virtual environment not found."
    fi
    echo "[+] Running install.sh to repair environment..."
    bash "${SCRIPT_DIR}/install.sh"

    if ! venv_is_valid; then
        echo "[ERROR] Virtual environment validation failed after install."
        exit 1
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

ensure_runtime_venv
ensure_admin_username_env
source "${SCRIPT_DIR}/venv/bin/activate"
normalize_env_blanks
runtime_sanity_check

echo "============================================"
echo "  NexusPenTest - AI Penetration Testing"
echo "  Starting server on 127.0.0.1:8000"
echo "============================================"
echo ""
if [ -x "bin/memory_ranker" ] || [ -x "bin/memory_ranker.exe" ]; then
    echo "  Native memory ranker: enabled"
else
    echo "  Native memory ranker: fallback mode"
fi
if [ -x "bin/swarm_planner" ] || [ -x "bin/swarm_planner.exe" ]; then
    echo "  Native swarm planner: enabled"
else
    echo "  Native swarm planner: fallback mode"
fi
echo "  Open: http://127.0.0.1:8000"
echo ""

python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
