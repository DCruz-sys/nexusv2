import tempfile
import unittest
from pathlib import Path

import app.database as dbmod
from app.jobs.runner import JobRunner


class LearningSourcesTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_path = dbmod.DATABASE_PATH
        dbmod.DATABASE_PATH = Path(self._tmpdir.name) / "learning_sources.db"
        dbmod.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        await dbmod.init_db()

    async def asyncTearDown(self):
        dbmod.DATABASE_PATH = self._original_path
        self._tmpdir.cleanup()

    async def test_learning_source_frontier_dedupe_and_checkpoint(self):
        source = await dbmod.upsert_learning_source(
            seed_url="https://book.hacktricks.wiki/",
            profile="aggressive_deep",
            enabled=True,
            metadata={"test": True},
        )
        source_id = str(source["id"])
        _, created_first = await dbmod.upsert_learning_frontier_url(
            source_id=source_id,
            url="https://book.hacktricks.wiki/",
            domain="book.hacktricks.wiki",
            depth=0,
            priority=100,
        )
        _, created_second = await dbmod.upsert_learning_frontier_url(
            source_id=source_id,
            url="https://book.hacktricks.wiki/",
            domain="book.hacktricks.wiki",
            depth=0,
            priority=100,
        )
        self.assertTrue(created_first)
        self.assertFalse(created_second)
        self.assertEqual(await dbmod.count_learning_frontier(source_id, status="queued"), 1)

        claimed = await dbmod.claim_learning_frontier(source_id, limit=1)
        self.assertEqual(len(claimed), 1)
        await dbmod.update_learning_frontier_status(claimed[0]["id"], status="done")
        self.assertEqual(await dbmod.count_learning_frontier(source_id, status="done"), 1)

        await dbmod.upsert_learning_checkpoint(source_id, {"foo": "bar"})
        checkpoint = await dbmod.get_learning_checkpoint(source_id)
        self.assertEqual(checkpoint["checkpoint"]["foo"], "bar")

    async def test_runner_schedules_due_learning_sources(self):
        source = await dbmod.upsert_learning_source(
            seed_url="https://book.hacktricks.wiki/",
            profile="aggressive_deep",
            enabled=True,
            metadata={"test": True},
        )
        source_id = str(source["id"])
        await dbmod.upsert_learning_frontier_url(
            source_id=source_id,
            url="https://book.hacktricks.wiki/",
            domain="book.hacktricks.wiki",
            depth=0,
            priority=100,
        )
        await dbmod.update_learning_source(source_id, next_run_at="2000-01-01T00:00:00+00:00")

        runner = JobRunner()
        await runner._schedule_learning_sources()

        jobs = await dbmod.list_jobs(limit=20, job_type="crawl_source")
        self.assertTrue(jobs)
        self.assertEqual(jobs[0]["type"], "crawl_source")
