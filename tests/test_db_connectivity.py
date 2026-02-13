import asyncio
import tempfile
import unittest
from pathlib import Path

import app.database as dbmod


class DBConnectivityTests(unittest.IsolatedAsyncioTestCase):
    async def test_get_db_connection_completes_quickly(self):
        original_path = dbmod.DATABASE_PATH
        with tempfile.TemporaryDirectory() as tmpdir:
            dbmod.DATABASE_PATH = Path(tmpdir) / "connectivity.db"
            dbmod.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
            try:
                db = await asyncio.wait_for(dbmod.get_db(), timeout=2)
                try:
                    cursor = await db.execute("SELECT 1 AS ok")
                    row = await cursor.fetchone()
                    self.assertEqual(int(row["ok"]), 1)
                finally:
                    await db.close()
            finally:
                dbmod.DATABASE_PATH = original_path
