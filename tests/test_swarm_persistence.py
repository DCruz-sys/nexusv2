import tempfile
import unittest
from pathlib import Path

import app.database as dbmod


class SwarmPersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_path = dbmod.DATABASE_PATH
        dbmod.DATABASE_PATH = Path(self._tmpdir.name) / "swarm_persistence.db"
        dbmod.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        await dbmod.init_db()

    async def asyncTearDown(self):
        dbmod.DATABASE_PATH = self._original_path
        self._tmpdir.cleanup()

    async def test_swarm_run_task_event_crud(self):
        run_id = "run-test-001"
        await dbmod.create_swarm_run(
            run_id=run_id,
            target="example.com",
            objective="assess",
            methodology="owasp",
            scan_type="quick",
            config={},
        )
        await dbmod.upsert_swarm_task(
            run_id=run_id,
            task_id="t1",
            agent="coordinator",
            task="plan",
            dependencies=[],
            priority=1,
            max_attempts=1,
            timeout_sec=30,
        )
        await dbmod.update_swarm_task(run_id, "t1", status="completed", result={"status": "ok"})
        await dbmod.add_swarm_event(run_id, "task_complete", {"task_id": "t1"})
        await dbmod.update_swarm_run(run_id, status="completed")

        run = await dbmod.get_swarm_run(run_id)
        self.assertEqual(run["status"], "completed")

        tasks = await dbmod.list_swarm_tasks(run_id)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["status"], "completed")
        self.assertEqual(tasks[0]["result"]["status"], "ok")

        events = await dbmod.list_swarm_events(run_id, limit=10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "task_complete")
