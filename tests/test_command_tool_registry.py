from nexus_v2.infra.tools.registry_yaml import ToolRegistry
from tools.command_tool import CommandTool


def test_registry_schema_fields_present():
    reg = ToolRegistry()
    reg.load()
    recipe = reg.get("nmap")
    assert recipe is not None
    assert recipe.tool_id == "nmap"
    assert recipe.category
    assert recipe.risk
    assert recipe.command_template
    assert recipe.parser_type
    assert recipe.scope_requirements


def test_command_tool_parser_plugin_json():
    reg = ToolRegistry()
    reg.load()
    recipe = reg.get("curl")
    assert recipe is not None
    # force parser for validation
    recipe = type(recipe)(**{**recipe.__dict__, "parser_type": "json"})
    tool = CommandTool(recipe)
    parsed = tool.parse('{"ok": true}')
    assert parsed["json"]["ok"] is True
