#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$ROOT_DIR/bin"
mkdir -p "$BIN_DIR"

echo "[1/2] Building Rust memory ranker..."
cargo build --release --manifest-path "$ROOT_DIR/rust/memory_ranker/Cargo.toml"
cp "$ROOT_DIR/rust/memory_ranker/target/release/memory_ranker" "$BIN_DIR/memory_ranker"

echo "[2/2] Building Go swarm planner..."
(cd "$ROOT_DIR/go/swarm_planner" && go build -o "$BIN_DIR/swarm_planner" .)

echo "Built accelerators in $BIN_DIR"
