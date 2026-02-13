from __future__ import annotations

import shlex
from dataclasses import dataclass

from tools.command_tool import CommandTool
from tools.exploit.metasploit_tool import MetasploitTool
from tools.network.nmap_tool import NmapTool
from tools.recon.amass_tool import AmassTool
from tools.recon.httpx_tool import HttpxTool
from tools.recon.subfinder_tool import SubfinderTool
from tools.registry import TOOL_REGISTRY, ToolMetadata
from tools.web.ffuf_tool import FfufTool
from tools.web.nuclei_tool import NucleiTool
from tools.web.sqlmap_tool import SqlmapTool

HIGH_VALUE = {
    "nmap": NmapTool,
    "nuclei": NucleiTool,
    "ffuf": FfufTool,
    "sqlmap": SqlmapTool,
    "amass": AmassTool,
    "subfinder": SubfinderTool,
    "httpx": HttpxTool,
}


@dataclass(frozen=True)
class GenericToolRecipe:
    tool_id: str
    name: str
    binary: str
    category: str
    risk: str
    command_template: str
    parser_type: str
    scope_requirements: list[str]
    args_template: list[str]
    timeout_sec_default: int = 300


def _template_to_argv(template: str) -> list[str]:
    raw = (template or "").strip()
    if not raw:
        return []
    return shlex.split(raw)


def _recipe_from_metadata(metadata: ToolMetadata) -> GenericToolRecipe:
    args_template = _template_to_argv(metadata.command_template)
    binary = args_template[0] if args_template else metadata.name
    return GenericToolRecipe(
        tool_id=metadata.name,
        name=metadata.name,
        binary=binary,
        category=metadata.category,
        risk=metadata.risk,
        command_template=metadata.command_template,
        parser_type=metadata.parser_type,
        scope_requirements=[metadata.scope_policy],
        args_template=args_template,
    )


def get_tool_wrapper(name: str):
    tool_name = (name or "").strip().lower()
    if tool_name in HIGH_VALUE:
        return HIGH_VALUE[tool_name]()
    if tool_name in {"metasploit", "msfconsole", "metasploit-framework"}:
        return MetasploitTool()

    metadata = TOOL_REGISTRY.get(tool_name)
    if not metadata:
        return None
    return CommandTool(_recipe_from_metadata(metadata))


def get_all_tool_wrappers() -> dict[str, object]:
    wrappers: dict[str, object] = {}
    for tool_name in sorted(TOOL_REGISTRY.keys()):
        wrapper = get_tool_wrapper(tool_name)
        if wrapper is not None:
            wrappers[tool_name] = wrapper
    return wrappers
