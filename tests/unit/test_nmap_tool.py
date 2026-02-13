from tools.network.nmap_tool import NmapTool


def test_nmap_parse_extracts_open_ports_and_services():
    output = """
    Host is up.
    80/tcp open http Apache httpd 2.4.57
    443/tcp open https nginx 1.24.0
    OS details: Linux 5.x
    | VULNERABLE: CVE-2024-1234
    """
    parsed = NmapTool().parse(output)
    assert len(parsed["open_ports"]) == 2
    assert parsed["os_detection"] == "Linux 5.x"
    assert any("CVE-2024-1234" in v for v in parsed["vulnerabilities"])
