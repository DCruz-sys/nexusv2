import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import app.database as dbmod


class JobQueueTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        dbmod.DATABASE_PATH = Path(self._tmpdir.name) / "test.db"
        dbmod.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        await dbmod.init_db()

    async def asyncTearDown(self):
        self._tmpdir.cleanup()

    async def test_enqueue_claim_complete(self):
        job_id = await dbmod.enqueue_job("scan", {"scan_id": "s1"})
        pending = await dbmod.count_pending_jobs("scan")
        self.assertEqual(pending, 1)

        claimed = await dbmod.claim_jobs("scan", limit=1)
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["id"], job_id)
        self.assertEqual(claimed[0]["status"], "running")

        await dbmod.complete_job(job_id)
        jobs = await dbmod.list_jobs(limit=10, job_type="scan")
        self.assertEqual(jobs[0]["status"], "completed")

    async def test_retry_backoff_flow(self):
        job_id = await dbmod.enqueue_job("distill", {"x": 1}, max_attempts=2)
        claimed = await dbmod.claim_jobs("distill", limit=1)
        self.assertEqual(len(claimed), 1)

        await dbmod.fail_job(job_id, "boom", retry_delay_sec=1)
        jobs = await dbmod.list_jobs(limit=10, job_type="distill")
        self.assertEqual(jobs[0]["status"], "queued")

    async def test_reclaim_stale_running_jobs(self):
        job_id = await dbmod.enqueue_job("scan", {"scan_id": "s2"})
        claimed = await dbmod.claim_jobs("scan", limit=1, worker_id="scan-0", lease_seconds=60)
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["status"], "running")

        db = await dbmod.get_db()
        try:
            stale = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
            await db.execute(
                "UPDATE job_queue SET lease_until = ?, heartbeat_at = ? WHERE id = ?",
                (stale, stale, job_id),
            )
            await db.commit()
        finally:
            await db.close()

        reclaimed = await dbmod.reclaim_stale_running_jobs()
        self.assertEqual(reclaimed, 1)
        jobs = await dbmod.list_jobs(limit=10, job_type="scan")
        self.assertEqual(jobs[0]["status"], "queued")

    async def test_heartbeat_extends_lease(self):
        job_id = await dbmod.enqueue_job("crawl", {"seed": "x"})
        claimed = await dbmod.claim_jobs("crawl", limit=1, worker_id="crawl-1", lease_seconds=30)
        self.assertEqual(len(claimed), 1)
        before = claimed[0]["lease_until"]
        await dbmod.heartbeat_job(job_id, worker_id="crawl-1", lease_seconds=120)
        jobs = await dbmod.list_jobs(limit=10, job_type="crawl")
        self.assertTrue(jobs[0]["lease_until"] >= before)
