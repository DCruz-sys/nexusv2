from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from typing import Any


class OutputParser(ABC):
    @abstractmethod
    def parse(self, output: str) -> dict[str, Any]:
        raise NotImplementedError


class PlainTextParser(OutputParser):
    def parse(self, output: str) -> dict[str, Any]:
        lines = [line for line in output.splitlines() if line.strip()]
        return {"raw": output, "line_count": len(lines), "lines": lines}


class JsonOutputParser(OutputParser):
    def parse(self, output: str) -> dict[str, Any]:
        parsed = json.loads(output) if output.strip() else {}
        return {"raw": output, "json": parsed}


class XmlOutputParser(OutputParser):
    def parse(self, output: str) -> dict[str, Any]:
        root = ET.fromstring(output)
        return {"raw": output, "xml_root": root.tag}


class GrepableOutputParser(OutputParser):
    _match = re.compile(r"Host:\s+(\S+)\s+\((.*?)\)\s+Ports:\s+(.+)")

    def parse(self, output: str) -> dict[str, Any]:
        hosts: list[dict[str, Any]] = []
        for line in output.splitlines():
            m = self._match.search(line)
            if not m:
                continue
            host, hostname, ports = m.groups()
            hosts.append({"host": host, "hostname": hostname, "ports": ports})
        return {"raw": output, "hosts": hosts}


PARSERS: dict[str, OutputParser] = {
    "plain_text": PlainTextParser(),
    "text": PlainTextParser(),
    "json": JsonOutputParser(),
    "xml": XmlOutputParser(),
    "grepable": GrepableOutputParser(),
}


def parser_for(parser_type: str) -> OutputParser:
    return PARSERS.get((parser_type or "plain_text").lower(), PARSERS["plain_text"])
