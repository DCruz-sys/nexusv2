#!/usr/bin/env bash
set -euo pipefail

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

uv pip compile requirements-runtime.in -o "$TMP_DIR/requirements-runtime.txt"
uv pip compile requirements-dev.in -o "$TMP_DIR/requirements-dev.txt"
uv pip compile requirements-research.in -o "$TMP_DIR/requirements-research.txt"

diff -u requirements-runtime.txt "$TMP_DIR/requirements-runtime.txt"
diff -u requirements-dev.txt "$TMP_DIR/requirements-dev.txt"
diff -u requirements-research.txt "$TMP_DIR/requirements-research.txt"

echo "Lockfiles are up to date."
