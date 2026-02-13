#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -x "${SCRIPT_DIR}/venv/bin/python" ]; then
  echo "[ERROR] venv not found. Run install.sh first."
  exit 1
fi

source "${SCRIPT_DIR}/venv/bin/activate"

echo "============================================"
echo "  Nexus v2 Worker"
echo "============================================"
echo ""

python -m nexus_v2.worker.main

