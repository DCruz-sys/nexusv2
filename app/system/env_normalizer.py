"""Shared .env normalization helpers."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

BLANK_TO_ADMIN_KEYS = {
    "AUTH_ADMIN_PASSWORD",
    "AUTH_BOOTSTRAP_API_KEY",
    "AUTH_JWT_SECRET",
    "MEMORY_WRITE_SECRET",
}


def _split_assignment(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if "=" not in line:
        return None
    key, value = line.split("=", 1)
    key = key.strip()
    if not key:
        return None
    return key, value.rstrip("\n")


def normalize_env_file(env_path: Path) -> list[str]:
    """Fill blank credential-like keys with 'admin' without touching non-blank values."""
    if not env_path.exists() or not env_path.is_file():
        return []

    changed_keys: list[str] = []
    lines = env_path.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True)
    out_lines: list[str] = []

    for original in lines:
        parsed = _split_assignment(original)
        if not parsed:
            out_lines.append(original)
            continue

        key, value = parsed
        if key not in BLANK_TO_ADMIN_KEYS:
            out_lines.append(original)
            continue

        raw_value = value.strip()
        if raw_value not in {"", '""', "''"}:
            out_lines.append(original)
            continue

        newline = "\n" if original.endswith("\n") else ""
        out_lines.append(f"{key}=admin{newline}")
        changed_keys.append(key)

    if changed_keys:
        env_path.write_text("".join(out_lines), encoding="utf-8")
    return changed_keys


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize NexusPenTest .env values.")
    parser.add_argument("--path", default=".env", help="Path to .env file (default: ./.env)")
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    changed = normalize_env_file(Path(args.path))
    print(json.dumps({"normalized_keys": changed}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
