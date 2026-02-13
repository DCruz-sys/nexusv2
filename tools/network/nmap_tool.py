import re
from typing import Any, Dict, Optional

from tools.base_tool import BaseTool


class NmapTool(BaseTool):
    def __init__(self):
        super().__init__("nmap", "nmap", "Network port scanner and service detector")

    async def execute(self, target: str, scan_type: str = "default", ports: Optional[str] = None, additional_args: str = "") -> str:
        normalized_target = await self.normalize_and_validate_target(target)
        cmd = ["nmap"]
        if scan_type == "quick":
            cmd += ["-T4", "-F"]
        elif scan_type == "full":
            cmd += ["-T4", "-p-", "-sV", "-sC"]
        elif scan_type == "stealth":
            cmd += ["-sS", "-T2", "-f"]
        elif scan_type == "vuln":
            cmd += ["-sV", "--script", "vuln"]
        else:
            cmd += ["-sV", "-sC"]
        if ports:
            cmd += ["-p", ports]
        if additional_args:
            cmd += additional_args.split()
        cmd.append(normalized_target)
        result = await self._run_command(cmd, timeout=600, target=normalized_target)
        return result.get("stdout", result.get("error", ""))

    def parse(self, output: str) -> Dict[str, Any]:
        parsed: Dict[str, Any] = {"open_ports": [], "services": [], "os_detection": None, "vulnerabilities": []}
        for m in re.finditer(r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)", output):
            p, proto, state, svc = m.groups()
            if state == "open":
                parsed["open_ports"].append({"port": int(p), "protocol": proto, "service": svc, "state": state})
        for m in re.finditer(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.*)", output):
            p, proto, svc, ver = m.groups()
            parsed["services"].append({"port": int(p), "protocol": proto, "service": svc, "version": ver.strip()})
        os_m = re.search(r"OS details: (.*)", output)
        if os_m:
            parsed["os_detection"] = os_m.group(1)
        parsed["vulnerabilities"] = [m[0] for m in re.findall(r"\|\s+(.*(CVE|VULNERABLE|vuln).*)", output, re.IGNORECASE)]
        return parsed
