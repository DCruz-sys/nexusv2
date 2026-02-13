import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app.database as dbmod
from app.engine.scanner import stop_all_scans


class StopAllScansTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        dbmod.DATABASE_PATH = Path(self._tmpdir.name) / "test.db"
        dbmod.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        await dbmod.init_db()

    async def asyncTearDown(self):
        self._tmpdir.cleanup()

    async def test_stop_all_handles_pkill_failures(self):
        with patch("subprocess.run", side_effect=RuntimeError("pkill failed")):
            await stop_all_scans()
