from tools.web.nuclei_tool import NucleiTool


def test_nuclei_parse_jsonl_findings():
    output = '{"template-id":"xss","host":"https://example.com"}\n{"template-id":"sqli","host":"https://example.com"}'
    parsed = NucleiTool().parse(output)
    assert parsed["count"] == 2
    assert parsed["findings"][0]["template-id"] == "xss"
