from tools.parsers import parser_for


def test_grepable_parser_extracts_hosts():
    output = "Host: 10.0.0.1 ()  Ports: 80/open/tcp//http///"
    parsed = parser_for("grepable").parse(output)
    assert parsed["hosts"][0]["host"] == "10.0.0.1"


def test_xml_parser_extracts_root():
    parsed = parser_for("xml").parse("<nmaprun></nmaprun>")
    assert parsed["xml_root"] == "nmaprun"
