from tools.command_tool import CommandTool
from tools.factory import get_all_tool_wrappers, get_tool_wrapper


def test_factory_returns_high_value_wrapper():
    wrapper = get_tool_wrapper("nmap")
    assert wrapper is not None
    assert wrapper.__class__.__name__ == "NmapTool"


def test_factory_returns_registry_backed_wrapper_for_non_high_value_tool():
    wrapper = get_tool_wrapper("dnsenum")
    assert wrapper is not None
    assert isinstance(wrapper, CommandTool)


def test_get_all_tool_wrappers_covers_registry_population():
    wrappers = get_all_tool_wrappers()
    assert "nmap" in wrappers
    assert "dnsenum" in wrappers
    assert len(wrappers) > 100
