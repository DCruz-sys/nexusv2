"""YAML-backed tool registry (v2).

Inspired by the "tool recipes" approach used in modern pentest agents, but
implemented as a small local loader with strict validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from nexus_v2.config import Settings, get_settings


@dataclass(frozen=True)
class ToolRecipe:
    name: str
    binary: str
    category: str
    risk_level: str
    args_template: list[str]
    hitl_default: bool = False
    timeout_sec_default: int = 300
    parameters: list[dict] | None = None
    output_rules: dict | None = None


class ToolRegistryError(RuntimeError):
    pass


class ToolRegistry:
    def __init__(self, *, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._recipes: dict[str, ToolRecipe] = {}

    def load(self) -> None:
        tools_dir = Path(self.settings.catalog_dir) / "tools"
        if not tools_dir.exists():
            self._recipes = {}
            return
        recipes: dict[str, ToolRecipe] = {}
        for path in sorted(tools_dir.glob("*.y*ml")):
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(payload, dict):
                raise ToolRegistryError(f"Invalid recipe format: {path}")
            recipe = self._parse_recipe(payload, source=str(path))
            recipes[recipe.name] = recipe
        self._recipes = recipes

    def _parse_recipe(self, payload: dict[str, Any], *, source: str) -> ToolRecipe:
        name = str(payload.get("name") or "").strip()
        binary = str(payload.get("binary") or "").strip()
        category = str(payload.get("category") or "misc").strip().lower()
        risk = str(payload.get("risk_level") or "low").strip().lower()
        args_template = payload.get("args_template") or payload.get("argv") or []
        if not isinstance(args_template, list):
            raise ToolRegistryError(f"{source}: args_template must be a list")
        args_template = [str(x) for x in args_template if str(x).strip()]
        if not name or not binary or not args_template:
            raise ToolRegistryError(f"{source}: recipe missing required fields (name/binary/args_template)")
        hitl_default = bool(payload.get("hitl_default") or False)
        timeout = int(payload.get("timeout_sec_default") or 300)
        parameters = payload.get("parameters")
        if parameters is not None and not isinstance(parameters, list):
            raise ToolRegistryError(f"{source}: parameters must be a list")
        output_rules = payload.get("output_rules")
        if output_rules is not None and not isinstance(output_rules, dict):
            raise ToolRegistryError(f"{source}: output_rules must be an object")
        return ToolRecipe(
            name=name,
            binary=binary,
            category=category,
            risk_level=risk,
            args_template=args_template,
            hitl_default=hitl_default,
            timeout_sec_default=timeout,
            parameters=parameters,
            output_rules=output_rules,
        )

    def get(self, name: str) -> ToolRecipe | None:
        return self._recipes.get(str(name or "").strip())

    def list(self) -> list[ToolRecipe]:
        return list(self._recipes.values())


tool_registry = ToolRegistry()

