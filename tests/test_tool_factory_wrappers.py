from tools.command_tool import CommandTool
from tools.factory import HIGH_VALUE, get_all_tool_wrappers, get_tool_wrapper
from tools.registry import TOOL_REGISTRY


def test_factory_returns_high_value_wrapper():
    wrapper = get_tool_wrapper("nmap")
    assert wrapper is not None
    assert wrapper.__class__.__name__ == "NmapTool"


def test_factory_returns_registry_backed_wrapper_for_non_high_value_tool():
    wrapper = get_tool_wrapper("dnsenum")
    assert wrapper is not None
    assert isinstance(wrapper, CommandTool)


def test_get_all_tool_wrappers_covers_full_registry_population():
    wrappers = get_all_tool_wrappers()
    assert set(wrappers.keys()) == set(TOOL_REGISTRY.keys())


def test_high_value_tools_use_native_wrappers():
    for tool_name, tool_cls in HIGH_VALUE.items():
        wrapper = get_tool_wrapper(tool_name)
        assert isinstance(wrapper, tool_cls)


def test_non_high_value_tools_use_command_tool():
    non_high_value = [name for name in TOOL_REGISTRY if name not in HIGH_VALUE]
    assert non_high_value
    sample = non_high_value[:25]
    for tool_name in sample:
        wrapper = get_tool_wrapper(tool_name)
        assert isinstance(wrapper, CommandTool)
