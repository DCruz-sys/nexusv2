import tempfile
import unittest
from pathlib import Path

import app.database as dbmod
import app.routes.system as sysmod


class ForensicsBundleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        base = Path(self._tmpdir.name)
        dbmod.DATABASE_PATH = base / "test.db"
        dbmod.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        sysmod.REPORTS_DIR = base / "reports"
        sysmod.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        await dbmod.init_db()

    async def asyncTearDown(self):
        self._tmpdir.cleanup()

    async def test_forensics_bundle_generation(self):
        scan_id = "scan-forensics-001"
        await dbmod.create_scan(scan_id, "example.lab", "quick", "owasp", {})
        await dbmod.update_scan(scan_id, status="completed", progress=100)
        await dbmod.add_scan_result(
            scan_id=scan_id,
            phase="recon",
            tool_name="nmap",
            command="nmap -sV example.lab",
            output="open ports detected",
            findings=["test finding"],
            severity="low",
            status="completed",
        )
        await dbmod.add_memory_audit_event(
            event_type="tool_exec_finish",
            actor="executor",
            session_id=scan_id,
            reason="unit_test",
            payload={"scan_id": scan_id},
        )

        payload = await sysmod.api_system_forensics(scan_id, _principal={"role": "admin"})
        self.assertEqual(payload["scan_id"], scan_id)
        self.assertIn("bundle_hash", payload)
        self.assertTrue(Path(payload["file"]).exists())
        self.assertIn("audit_integrity", payload)

