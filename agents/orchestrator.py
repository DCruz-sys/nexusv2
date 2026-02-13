import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from agents.cve_intel_agent import CVEIntelligenceAgent
from agents.exploit_agent import ExploitAgent
from agents.recon_agent import ReconAgent
from agents.report_agent import ReportGeneratorAgent
from agents.v3.recon_agent import ReconAgent as ReconAgentV3
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
        self.use_v3_agents = os.getenv("USE_V3_AGENTS", "false").lower() == "true"

    async def initialize(self) -> None:
        await self.memory.initialize()
        v2_recon = ReconAgent(self.nim, self.memory, self.guardrails)
        v3_recon = ReconAgentV3(self.nim, self.memory)
        self.agents = {
            "recon": v3_recon if self.use_v3_agents else v2_recon,
            "recon_v2": v2_recon,
            "recon_v3": v3_recon,
            "vuln_scan": VulnScanAgent(self.nim, self.memory, self.guardrails),
            "cve_intel": CVEIntelligenceAgent(self.nim, self.memory, self.guardrails),
            "exploit": ExploitAgent(self.nim, self.memory, self.guardrails),
            "report": ReportGeneratorAgent(self.nim, self.memory, self.guardrails),
        }

    async def execute_full_pentest(self, target: str, scope: Dict[str, Any], task_id: Optional[str] = None) -> Dict[str, Any]:
        task_id = task_id or str(uuid.uuid4())
        results: Dict[str, Any] = {
            "task_id": task_id,
            "target": target,
            "scope": scope,
            "started_at": datetime.now().isoformat(),
            "use_v3_agents": self.use_v3_agents,
            "phases": {},
            "experience_records": [],
            "reinforcement_metrics": [],
        }
        recon = await self._run_phase(
            "reconnaissance",
            self.agents["recon"],
            {"type": "recon", "description": f"Conduct reconnaissance on {target}", "target": target, "scope": scope},
            results,
        )
        results["phases"]["reconnaissance"] = recon
        vuln = await self._run_phase(
            "vulnerability_scanning",
            self.agents["vuln_scan"],
            {"description": "Scan discovered assets for vulnerabilities", "scope": scope},
            results,
        )
        results["phases"]["vulnerability_scanning"] = vuln
        enriched = await self.agents["cve_intel"].analyze_vulnerabilities(vuln)
        self._emit_learning_metrics("cve_intelligence", self.agents["cve_intel"], {"enriched_vulnerabilities": enriched}, results)
        results["phases"]["cve_intelligence"] = {"enriched_vulnerabilities": enriched}
        exploitation = await self._controlled_exploitation(enriched, scope)
        self._emit_learning_metrics("exploitation", self.agents["exploit"], exploitation, results)
        results["phases"]["exploitation"] = exploitation
        results["report"] = await self.agents["report"].generate_report(results)
        self._emit_learning_metrics("report", self.agents["report"], results["report"], results)
        results["completed_at"] = datetime.now().isoformat()
        results["status"] = "completed"
        return results

    async def _run_phase(self, phase_name: str, agent: Any, task: Dict[str, Any], results: Dict[str, Any]) -> Dict[str, Any]:
        if hasattr(agent, "learn_and_execute"):
            phase_result = await agent.learn_and_execute(task)
        else:
            phase_result = await agent.run(task)
        self._emit_learning_metrics(phase_name, agent, phase_result, results)
        return phase_result

    def _emit_learning_metrics(self, phase_name: str, agent: Any, phase_result: Dict[str, Any], results: Dict[str, Any]) -> None:
        experience = getattr(agent, "current_experience", None)
        if experience:
            results["experience_records"].append({"phase": phase_name, **experience.to_dict()})

        exploration_rate = None
        if hasattr(agent, "strategy_params"):
            exploration_rate = agent.strategy_params.get("exploration_rate")

        results["reinforcement_metrics"].append(
            {
                "phase": phase_name,
                "agent": getattr(agent, "name", phase_name),
                "success": bool(phase_result.get("success", False)) if isinstance(phase_result, dict) else False,
                "exploration_rate": exploration_rate,
            }
        )

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
