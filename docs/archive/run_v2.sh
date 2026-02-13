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
echo "  Nexus v2 - Local-First Engagement+RunGraph"
echo "  Starting API on 127.0.0.1:8001"
echo "============================================"
echo "  UI: http://127.0.0.1:8001/v2"
echo ""

python -m uvicorn nexus_v2.api.main:app --host 127.0.0.1 --port 8001

