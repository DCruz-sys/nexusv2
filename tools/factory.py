from __future__ import annotations

from tools.command_tool import CommandTool
from tools.exploit.metasploit_tool import MetasploitTool
from tools.network.nmap_tool import NmapTool
from tools.recon.amass_tool import AmassTool
from tools.recon.httpx_tool import HttpxTool
from tools.recon.subfinder_tool import SubfinderTool
from tools.registry import TOOL_REGISTRY
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


class GenericToolRecipe:
    def __init__(self, name: str, command_template: str, parser_type: str):
        self.name = name
        self.binary = name
        self.command_template = command_template
        self.parser_type = parser_type
        self.timeout_sec_default = 300


def get_tool_wrapper(name: str):
    tool_name = (name or "").strip().lower()
    if tool_name in HIGH_VALUE:
        return HIGH_VALUE[tool_name]()
    if tool_name in {"metasploit", "msfconsole", "metasploit-framework"}:
        return MetasploitTool()

    metadata = TOOL_REGISTRY.get(tool_name)
    if not metadata:
        return None
    return CommandTool(GenericToolRecipe(metadata.name, metadata.command_template, metadata.parser_type))
