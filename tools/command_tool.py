from __future__ import annotations

from typing import Any

from nexus_v2.infra.tools.host_exec import build_argv
from nexus_v2.infra.tools.registry_yaml import ToolRecipe
from tools.base_tool import BaseTool
from tools.parsers import parser_for


class CommandTool(BaseTool):
    def __init__(self, recipe: ToolRecipe):
        super().__init__(recipe.name, recipe.binary, f"Registry-backed wrapper for {recipe.name}")
        self.recipe = recipe

    async def execute(self, target: str, timeout: int = 300, use_docker: bool = True, **params: Any) -> str:
        argv = build_argv(recipe=self.recipe, target=target, params=params)
        result = await self._run_command(argv, timeout=timeout or self.recipe.timeout_sec_default, use_docker=use_docker)
        return result.get("stdout", result.get("error", ""))

    def parse(self, output: str) -> dict[str, Any]:
        return parser_for(self.recipe.parser_type).parse(output)
