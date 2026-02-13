import tempfile
import unittest
from pathlib import Path

import app.database as dbmod


class AuditChainTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        dbmod.DATABASE_PATH = Path(self._tmpdir.name) / "test.db"
        dbmod.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        await dbmod.init_db()

    async def asyncTearDown(self):
        self._tmpdir.cleanup()

    async def test_chain_verification_passes_for_normal_writes(self):
        await dbmod.add_memory_audit_event(
            event_type="test_event_a",
            actor="test",
            session_id="s1",
            reason="unit_test",
            payload={"a": 1},
        )
        await dbmod.add_memory_audit_event(
            event_type="test_event_b",
            actor="test",
            session_id="s1",
            reason="unit_test",
            payload={"b": 2},
        )
        verification = await dbmod.verify_memory_audit_chain(limit=200)
        self.assertTrue(verification["valid"])
        self.assertEqual(verification["broken"], 0)
        self.assertGreaterEqual(verification["checked"], 2)

    async def test_chain_detects_tampering(self):
        await dbmod.add_memory_audit_event(
            event_type="test_event",
            actor="test",
            session_id="s2",
            reason="unit_test",
            payload={"secure": True},
        )
        db = await dbmod.get_db()
        try:
            await db.execute(
                "UPDATE memory_audit_log SET payload = ? WHERE id = (SELECT MAX(id) FROM memory_audit_log)",
                ('{"secure":false}',),
            )
            await db.commit()
        finally:
            await db.close()

        verification = await dbmod.verify_memory_audit_chain(limit=200)
        self.assertFalse(verification["valid"])
        self.assertGreaterEqual(verification["broken"], 1)

    async def test_backfill_repairs_legacy_rows(self):
        db = await dbmod.get_db()
        try:
            await db.execute(
                """INSERT INTO memory_audit_log
                   (event_type, actor, session_id, reason, payload, signature, prev_hash, event_hash, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    "legacy_event",
                    "legacy",
                    "legacy-session",
                    "legacy_insert",
                    '{"legacy":true}',
                    "",
                    "",
                    "",
                    dbmod._utcnow_iso(),
                ),
            )
            await db.commit()
        finally:
            await db.close()

        pre = await dbmod.verify_memory_audit_chain(limit=200)
        self.assertFalse(pre["valid"])

        backfill = await dbmod.backfill_memory_audit_chain()
        self.assertGreaterEqual(backfill["updated"], 1)

        post = await dbmod.verify_memory_audit_chain(limit=200)
        self.assertTrue(post["valid"])

