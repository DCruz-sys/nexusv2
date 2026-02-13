"""Kali tool catalog loaded from normalized catalog_v2 registry."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

TOOL_CATEGORIES = {
    "information_gathering": "Information Gathering",
    "vulnerability_analysis": "Vulnerability",
    "web_application": "Web",
    "database_assessment": "Database",
    "password_attacks": "Passwords",
    "wireless_attacks": "Wireless",
    "reverse_engineering": "Reverse Engineering",
    "exploitation_tools": "Exploitation",
    "social_engineering": "Social Engineering",
    "sniffing_spoofing": "Sniffing Spoofing",
    "post_exploitation": "Post Exploitation",
    "forensics": "Forensics",
    "reporting_tools": "Reporting",
    "misc": "Misc",
}


def _catalog_path() -> Path:
    root = Path(__file__).resolve().parents[2]
    return root / "catalog_v2" / "tools" / "kali_catalog.yaml"


def _load_tools() -> list[dict[str, Any]]:
    path = _catalog_path()
    if not path.exists():
        return []
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    tools = payload.get("tools") if isinstance(payload, dict) else []
    if not isinstance(tools, list):
        return []

    normalized: list[dict[str, Any]] = []
    for row in tools:
        if not isinstance(row, dict):
            continue
        name = str(row.get("tool_id") or row.get("name") or "").strip()
        if not name:
            continue
        normalized.append(
            {
                "name": name,
                "category": str(row.get("category") or "misc"),
                "description": str(row.get("description") or ""),
                "command_template": str(row.get("command_template") or "{binary} {target}"),
                "default_args": str(row.get("default_args") or "").strip(),
                "risk_level": str(row.get("risk") or row.get("risk_level") or "low"),
                "tags": row.get("tags") or [],
                "parser_type": str(row.get("parser_type") or "plain_text"),
                "scope_requirements": row.get("scope_requirements") or ["target"],
            }
        )
    return normalized


KALI_TOOLS = _load_tools()
KALI_TOOL_NAMES = {t["name"] for t in KALI_TOOLS}


def get_tools_by_category(category: str) -> list:
    return [t for t in KALI_TOOLS if t["category"] == category]


def get_tool(name: str) -> dict | None:
    for t in KALI_TOOLS:
        if t["name"] == name:
            return t
    return None


def search_tools(query: str) -> list:
    q = query.lower()
    results = []
    for t in KALI_TOOLS:
        name = str(t.get("name") or "").lower()
        desc = str(t.get("description") or "").lower()
        tags = [str(tag).lower() for tag in t.get("tags", [])]

        if q in name or q in desc or any(q in tag for tag in tags):
            results.append(t)
    return results


def get_all_categories() -> dict:
    return TOOL_CATEGORIES
