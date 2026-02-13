from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

from app.frameworks.kali_tools import KALI_TOOLS


@dataclass(frozen=True)
class ToolMetadata:
    name: str
    category: str
    risk: str
    command_template: str
    parser_type: str
    scope_policy: str


def _normalize(row: dict) -> ToolMetadata | None:
    name = str(row.get("name") or "").strip().lower()
    if not name:
        return None
    return ToolMetadata(
        name=name,
        category=str(row.get("category") or "misc"),
        risk=str(row.get("risk") or row.get("risk_level") or "low"),
        command_template=str(row.get("command_template") or f"{name} {{args}} {{target}}"),
        parser_type=str(row.get("parser_type") or "plain_text"),
        scope_policy=str(row.get("scope_policy") or "target_required"),
    )


def load_registry() -> Dict[str, ToolMetadata]:
    merged: Dict[str, ToolMetadata] = {}
    for tool in KALI_TOOLS:
        normalized = _normalize(tool)
        if normalized:
            merged[normalized.name] = normalized
    dump = Path(__file__).resolve().parents[1] / "kali_tools_dump.json"
    if dump.exists():
        rows = json.loads(dump.read_text(encoding="utf-8"))
        for row in rows:
            normalized = _normalize(row)
            if normalized:
                merged.setdefault(normalized.name, normalized)
    return merged


TOOL_REGISTRY = load_registry()
