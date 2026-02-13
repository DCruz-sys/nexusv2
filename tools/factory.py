from __future__ import annotations

from nexus_v2.infra.tools.registry_yaml import tool_registry
from tools.command_tool import CommandTool
from tools.exploit.metasploit_tool import MetasploitTool
from tools.network.nmap_tool import NmapTool
from tools.web.ffuf_tool import FfufTool
from tools.web.nuclei_tool import NucleiTool
from tools.web.sqlmap_tool import SqlmapTool


def get_tool_wrapper(name: str):
    tool_name = (name or "").strip().lower()
    if tool_name == "nmap":
        return NmapTool()
    if tool_name == "nuclei":
        return NucleiTool()
    if tool_name == "ffuf":
        return FfufTool()
    if tool_name == "sqlmap":
        return SqlmapTool()
    if tool_name in {"metasploit", "msfconsole", "metasploit-framework"}:
        return MetasploitTool()

    recipe = tool_registry.get(tool_name)
    if not recipe:
        return None
    return CommandTool(recipe)
