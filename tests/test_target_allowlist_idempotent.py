import tempfile
import unittest
from pathlib import Path

import app.database as dbmod


class TargetAllowlistIdempotentTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        dbmod.DATABASE_PATH = Path(self._tmpdir.name) / "test.db"
        dbmod.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        await dbmod.init_db()

    async def asyncTearDown(self):
        self._tmpdir.cleanup()

    async def test_add_target_rule_is_idempotent_with_normalization(self):
        rid1 = await dbmod.add_target_rule("domain", "scanme.nmap.org", created_by="t", enabled=True)
        rid2 = await dbmod.add_target_rule("domain", "https://SCANME.NMAP.ORG/", created_by="t2", enabled=True)
        self.assertEqual(rid1, rid2)

        rules = await dbmod.list_target_rules(enabled_only=False)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["type"], "domain")
        self.assertEqual(rules[0]["pattern"], "scanme.nmap.org")

