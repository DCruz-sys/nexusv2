"""Tool and accelerator capability checks for Kali runtime."""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Iterable

from app.config import ENABLE_NATIVE_ACCELERATORS, MEMORY_RANKER_BIN, SWARM_PLANNER_BIN
from app.database import list_tool_capabilities, upsert_tool_capability
from app.frameworks.kali_tools import KALI_TOOLS

ESSENTIAL_TOOLS = {
    "nmap",
    "nikto",
    "gobuster",
    "whatweb",
    "sqlmap",
    "masscan",
    "hydra",
    "curl",
    "wget",
    "dig",
    "host",
    "dnsenum",
}


def _is_executable(path: Path) -> bool:
    return path.exists() and path.is_file() and os.access(path, os.X_OK)


def _iter_catalog_tools() -> set[str]:
    names = {str(row.get("name", "")).strip() for row in KALI_TOOLS}
    return {name for name in names if name}


async def refresh_tool_capabilities(tool_names: Iterable[str] | None = None):
    """Persist current tool availability to the database."""
    names = set(tool_names or [])
    if not names:
        names = _iter_catalog_tools() | ESSENTIAL_TOOLS

    for tool_name in sorted(names):
        path = shutil.which(tool_name)
        await upsert_tool_capability(
            tool_name=tool_name,
            available=bool(path),
            details={"path": path or "", "source": "startup_scan"},
        )

    ranker = Path(MEMORY_RANKER_BIN)
    planner = Path(SWARM_PLANNER_BIN)
    await upsert_tool_capability(
        tool_name="memory_ranker",
        available=_is_executable(ranker),
        details={"path": str(ranker), "feature_flag": ENABLE_NATIVE_ACCELERATORS},
    )
    await upsert_tool_capability(
        tool_name="swarm_planner",
        available=_is_executable(planner),
        details={"path": str(planner), "feature_flag": ENABLE_NATIVE_ACCELERATORS},
    )


async def get_capability_summary() -> dict:
    rows = await list_tool_capabilities(limit=2000)
    available = [row for row in rows if int(row.get("available") or 0) == 1]
    unavailable = [row for row in rows if int(row.get("available") or 0) == 0]
    return {
        "total": len(rows),
        "available": len(available),
        "unavailable": len(unavailable),
        "accelerators": {
            "memory_ranker": next((row for row in rows if row.get("tool_name") == "memory_ranker"), None),
            "swarm_planner": next((row for row in rows if row.get("tool_name") == "swarm_planner"), None),
        },
        "missing_essential": sorted(
            tool for tool in ESSENTIAL_TOOLS
            if not next((row for row in rows if row.get("tool_name") == tool and int(row.get("available") or 0) == 1), None)
        ),
    }

