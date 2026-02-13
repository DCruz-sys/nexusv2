import os
import time
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
from core.telemetry import telemetry


class PentestOrchestrator:
    def __init__(self):
        self.nim = NVIDIANIMProvider()
        self.memory = MemorySystem(self.nim)
        self.guardrails = SecurityGuardrails(self.nim)
        self.agents: Dict[str, Any] = {}
        self.use_v3_agents = os.getenv("USE_V3_AGENTS", "true").lower() == "true"

    async def initialize(self) -> None:
        await self.memory.initialize()
        self.agents = {
            "recon": ReconAgent(self.nim, self.memory),
            "vuln_scan": VulnScanAgent(self.nim, self.memory),
            "cve_intel": CVEIntelligenceAgent(self.nim, self.memory, self.guardrails),
            "exploit": ExploitAgent(self.nim, self.memory),
            "report": ReportGeneratorAgent(self.nim, self.memory, self.guardrails),
        }

    async def execute_full_pentest(self, target: str, scope: Dict[str, Any], task_id: Optional[str] = None) -> Dict[str, Any]:
        task_id = task_id or str(uuid.uuid4())
        results: Dict[str, Any] = {"task_id": task_id, "target": target, "scope": scope, "started_at": datetime.now().isoformat(), "phases": {}}
        with telemetry.span("pentest.execute_full", attributes={"task_id": task_id, "target": target}):
            telemetry.trace_event(task_id=task_id, name="pentest.start", input_payload={"target": target, "scope": scope, "use_v3_agents": self.use_v3_agents})
            recon_start = time.monotonic()
            recon = await self.agents["recon"].run({"description": f"Conduct reconnaissance on {target}", "target": target, "scope": scope, "task_id": task_id})
            status = "success" if recon.get("success", True) else "failed"
            results["phases"]["reconnaissance"] = recon
            telemetry.observe_phase(task_id=task_id, phase="reconnaissance", status=status, started_at=recon_start, details={"phase_result": status})
            self._record_phase_usage(task_id=task_id, agent="recon", phase_result=recon)

            vuln_start = time.monotonic()
            vuln = await self.agents["vuln_scan"].run({"description": "Scan discovered assets for vulnerabilities", "target": target, "scope": scope, "task_id": task_id})
            status = "success" if vuln.get("success", True) else "failed"
            results["phases"]["vulnerability_scanning"] = vuln
            telemetry.observe_phase(task_id=task_id, phase="vulnerability_scanning", status=status, started_at=vuln_start, details={"phase_result": status})
            self._record_phase_usage(task_id=task_id, agent="vuln_scan", phase_result=vuln)

            cve_start = time.monotonic()
            enriched = await self.agents["cve_intel"].analyze_vulnerabilities(vuln)
            cve_result = {"enriched_vulnerabilities": enriched}
            results["phases"]["cve_intelligence"] = cve_result
            telemetry.observe_phase(task_id=task_id, phase="cve_intelligence", status="success", started_at=cve_start, details={"enriched_count": len(enriched or [])})
            self._record_phase_usage(task_id=task_id, agent="cve_intel", phase_result=cve_result)

            exploit_start = time.monotonic()
            exploitation = await self._controlled_exploitation(enriched, scope)
            status = "approved" if not exploitation.get("skipped") else "blocked"
            results["phases"]["exploitation"] = exploitation
            telemetry.observe_phase(task_id=task_id, phase="exploitation", status=status, started_at=exploit_start, details={"skipped": len(exploitation.get("skipped", []))})
            self._record_phase_usage(task_id=task_id, agent="exploit", phase_result=exploitation)

            report_start = time.monotonic()
            report = await self.agents["report"].generate_report(results)
            results["report"] = report
            telemetry.observe_phase(task_id=task_id, phase="reporting", status="success", started_at=report_start)
            self._record_phase_usage(task_id=task_id, agent="report", phase_result=report)

            results["completed_at"] = datetime.now().isoformat()
            results["status"] = "completed"

        results["telemetry"] = telemetry.get_task_totals(task_id)
        telemetry.trace_event(task_id=task_id, name="pentest.completed", output_payload={"status": results.get("status"), "telemetry": results["telemetry"]})
        return results

    @staticmethod
    def _record_phase_usage(task_id: str, agent: str, phase_result: Dict[str, Any]) -> None:
        usage = phase_result.get("usage") if isinstance(phase_result.get("usage"), dict) else {}
        tokens = phase_result.get("tokens") if isinstance(phase_result.get("tokens"), dict) else {}
        telemetry.record_usage(task_id=task_id, agent=agent, cost_usd=float(phase_result.get("cost_usd") or usage.get("cost_usd") or 0.0), prompt_tokens=int(usage.get("prompt_tokens") or tokens.get("prompt") or 0), completion_tokens=int(usage.get("completion_tokens") or tokens.get("completion") or 0), total_tokens=int(usage.get("total_tokens") or tokens.get("total") or 0), reward=float(phase_result.get("reward") or 0.0))

    async def _controlled_exploitation(self, vulnerabilities: List[Dict[str, Any]], scope: Dict[str, Any]) -> Dict[str, Any]:
        require_approval = scope.get("require_approval", True)
        if require_approval:
            return {"attempted": [], "successful": [], "failed": [], "skipped": [{"reason": "Awaiting human approval"}]}
        return await self.agents["exploit"].run({"description": "Attempt controlled exploitation", "scope": scope, "vulnerabilities": vulnerabilities})

    async def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        async with self.memory.db_pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM pentest_sessions WHERE id = $1", task_id)
        return dict(row) if row else None

    async def close(self) -> None:
        await self.memory.close()
