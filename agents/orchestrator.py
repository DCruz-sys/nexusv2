import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from agents.cve_intel_agent import CVEIntelligenceAgent
from agents.exploit_agent import ExploitAgent
from agents.recon_agent import ReconAgent
from agents.report_agent import ReportGeneratorAgent
from agents.vuln_scan_agent import VulnScanAgent
from core.guardrails import SecurityGuardrails
from core.memory_system import MemorySystem
from core.nvidia_nim_provider import NVIDIANIMProvider


class PentestOrchestrator:
    def __init__(self):
        self.nim = NVIDIANIMProvider()
        self.memory = MemorySystem(self.nim)
        self.guardrails = SecurityGuardrails(self.nim)
        self.agents: Dict[str, Any] = {}

    async def initialize(self) -> None:
        await self.memory.initialize()
        self.agents = {
            "recon": ReconAgent(self.nim, self.memory, self.guardrails),
            "vuln_scan": VulnScanAgent(self.nim, self.memory, self.guardrails),
            "cve_intel": CVEIntelligenceAgent(self.nim, self.memory, self.guardrails),
            "exploit": ExploitAgent(self.nim, self.memory, self.guardrails),
            "report": ReportGeneratorAgent(self.nim, self.memory, self.guardrails),
        }

    async def execute_full_pentest(self, target: str, scope: Dict[str, Any], task_id: Optional[str] = None) -> Dict[str, Any]:
        task_id = task_id or str(uuid.uuid4())
        results: Dict[str, Any] = {"task_id": task_id, "target": target, "scope": scope, "started_at": datetime.now().isoformat(), "phases": {}}
        recon = await self.agents["recon"].run({"description": f"Conduct reconnaissance on {target}", "target": target, "scope": scope})
        results["phases"]["reconnaissance"] = recon
        vuln = await self.agents["vuln_scan"].run({"description": "Scan discovered assets for vulnerabilities", "scope": scope})
        results["phases"]["vulnerability_scanning"] = vuln
        enriched = await self.agents["cve_intel"].analyze_vulnerabilities(vuln)
        results["phases"]["cve_intelligence"] = {"enriched_vulnerabilities": enriched}
        results["phases"]["exploitation"] = await self._controlled_exploitation(enriched, scope)
        results["report"] = await self.agents["report"].generate_report(results)
        results["completed_at"] = datetime.now().isoformat()
        results["status"] = "completed"
        return results

    async def _controlled_exploitation(self, vulnerabilities: List[Dict[str, Any]], scope: Dict[str, Any]) -> Dict[str, Any]:
        require_approval = scope.get("require_approval", True)
        if require_approval:
            return {"attempted": [], "successful": [], "failed": [], "skipped": [{"reason": "Awaiting human approval"}]}
        return {"attempted": [], "successful": [], "failed": [], "skipped": []}

    async def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        async with self.memory.db_pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM pentest_sessions WHERE id = $1", task_id)
        return dict(row) if row else None

    async def close(self) -> None:
        await self.memory.close()
