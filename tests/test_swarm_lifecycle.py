import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app.database as dbmod
from app.ai.agent_swarm import Agent, agent_swarm
from app.security.allowlist import TargetNotAllowedError


async def _fake_agent_execute(self, task: str, context: str = "") -> dict:
    return {
        "agent": getattr(self, "name", "MockAgent"),
        "prompt_key": getattr(self, "prompt_key", "mock"),
        "task": task,
        "response": f"mock-response:{task[:48]}",
        "model_used": "mock-model",
        "task_type": "mock",
    }


class SwarmLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_path = dbmod.DATABASE_PATH
        dbmod.DATABASE_PATH = Path(self._tmpdir.name) / "swarm.db"
        dbmod.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        await dbmod.init_db()

    async def asyncTearDown(self):
        dbmod.DATABASE_PATH = self._original_path
        self._tmpdir.cleanup()

    async def test_swarm_run_create_execute_and_stop(self):
        await dbmod.add_target_rule("domain", "example.com", created_by="test", enabled=True)
        with patch.object(Agent, "execute", new=_fake_agent_execute):
            run_id = await agent_swarm.create_persistent_run(
                target="example.com",
                objective="Enumerate and assess target attack surface",
                methodology="owasp",
                scan_type="quick",
                config={},
            )
            result = await agent_swarm.execute_persistent_run(run_id)
            self.assertEqual(result["run"]["status"], "completed")
            self.assertTrue(result["tasks"])
            self.assertTrue(all(t["status"] == "completed" for t in result["tasks"]))

            # stop call should be idempotent even after completion
            await agent_swarm.stop_persistent_run(run_id)
            post = await agent_swarm.get_run_bundle(run_id)
            self.assertIn(post["run"]["status"], {"completed", "stopping"})

    async def test_swarm_run_dry_run_completes_without_model_calls(self):
        await dbmod.add_target_rule("domain", "example.com", created_by="test", enabled=True)
        with patch.object(Agent, "execute", side_effect=AssertionError("planner/model call should not run in dry_run")):
            run_id = await agent_swarm.create_persistent_run(
                target="example.com",
                objective="Dry run flow",
                methodology="owasp",
                scan_type="quick",
                config={"dry_run": True},
            )
        result = await agent_swarm.execute_persistent_run(run_id)
        self.assertEqual(result["run"]["status"], "completed")
        self.assertTrue(result["tasks"])
        self.assertTrue(all(t["status"] == "completed" for t in result["tasks"]))

    async def test_swarm_target_must_be_allowlisted(self):
        with patch.object(Agent, "execute", new=_fake_agent_execute):
            with self.assertRaises(TargetNotAllowedError):
                await agent_swarm.create_persistent_run(
                    target="not-allowed.example",
                    objective="Try to run out of scope",
                    methodology="owasp",
                    scan_type="quick",
                    config={},
                )
