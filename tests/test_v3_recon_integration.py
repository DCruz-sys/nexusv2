import asyncio
import os

from agents.v3.recon_agent import ReconAgent
from agents import orchestrator as orchestrator_module


class DummyNIM:
    async def call_async(self, **kwargs):
        return {
            "content": '{"is_complete": false, "is_impossible": false, "reasoning": "scan", "next_action": "nmap", "expected_result": "ports", "tool": "nmap", "params": {"target": "example.com", "scan_type": "default"}}'
        }

    async def get_embedding(self, text: str):
        return [0.1, 0.2, 0.3]


class DummyMemory:
    def __init__(self):
        self.stored = []

    async def initialize(self):
        return None

    async def close(self):
        return None

    async def query_episodic(self, query_text, agent_type=None, limit=5):
        return []

    async def store_episodic(self, **kwargs):
        self.stored.append(kwargs)


class DummyGuardrails:
    def __init__(self, _nim):
        self.nim = _nim


class DummyRunAgent:
    def __init__(self, name, *args, **kwargs):
        self.name = name

    async def run(self, task):
        return {"success": True, "agent": self.name, "task": task}


class DummyCVEAgent(DummyRunAgent):
    async def analyze_vulnerabilities(self, vuln):
        return [{"cve": "CVE-2024-0001", "source": vuln.get("agent")}]


class DummyReportAgent(DummyRunAgent):
    async def generate_report(self, results):
        return {"success": True, "report_id": results["task_id"]}


def test_v3_recon_agent_stores_episodic_and_updates_exploration(monkeypatch):
    agent = ReconAgent(DummyNIM(), DummyMemory())

    async def fake_execute(self, **kwargs):
        return "22/tcp open ssh OpenSSH 8.2"

    monkeypatch.setattr("tools.network.nmap_tool.NmapTool.execute", fake_execute)

    before = agent.strategy_params["exploration_rate"]
    result = asyncio.run(
        agent.learn_and_execute({"type": "recon", "description": "Recon target", "target": "example.com"})
    )

    assert result["success"] is True
    assert len(agent.memory.stored) == 1
    assert agent.strategy_params["exploration_rate"] < before


def test_orchestrator_v3_path_emits_experience_and_reinforcement_metrics(monkeypatch):
    monkeypatch.setenv("USE_V3_AGENTS", "true")
    monkeypatch.setattr(orchestrator_module, "NVIDIANIMProvider", DummyNIM)
    monkeypatch.setattr(orchestrator_module, "MemorySystem", lambda nim: DummyMemory())
    monkeypatch.setattr(orchestrator_module, "SecurityGuardrails", DummyGuardrails)
    monkeypatch.setattr(orchestrator_module, "VulnScanAgent", lambda *args, **kwargs: DummyRunAgent("VulnScanAgent"))
    monkeypatch.setattr(orchestrator_module, "CVEIntelligenceAgent", lambda *args, **kwargs: DummyCVEAgent("CVEIntelligenceAgent"))
    monkeypatch.setattr(orchestrator_module, "ExploitAgent", lambda *args, **kwargs: DummyRunAgent("ExploitAgent"))
    monkeypatch.setattr(orchestrator_module, "ReportGeneratorAgent", lambda *args, **kwargs: DummyReportAgent("ReportGeneratorAgent"))

    async def fake_execute(self, **kwargs):
        return "80/tcp open http nginx"

    monkeypatch.setattr("tools.network.nmap_tool.NmapTool.execute", fake_execute)

    orchestrator = orchestrator_module.PentestOrchestrator()
    asyncio.run(orchestrator.initialize())
    result = asyncio.run(orchestrator.execute_full_pentest("example.com", {"require_approval": False}))

    assert result["use_v3_agents"] is True
    assert len(result["experience_records"]) >= 1
    assert any(metric["phase"] == "reconnaissance" and metric["exploration_rate"] is not None for metric in result["reinforcement_metrics"])
    assert len(orchestrator.agents["recon"].memory.stored) == 1
    os.environ.pop("USE_V3_AGENTS", None)
