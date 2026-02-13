import asyncio
import tempfile
import unittest
from pathlib import Path

import app.database as dbmod
import app.ai.memory_manager as mm_mod
from app.ai.memory_manager import MemoryManager


class ChatMemoryScopeTests(unittest.IsolatedAsyncioTestCase):
    async def test_durable_chat_memory_can_write_global_while_snapshot_stays_session(self):
        original_path = dbmod.DATABASE_PATH
        original_nim_extraction = mm_mod.MEMORY_ENABLE_NIM_EXTRACTION
        with tempfile.TemporaryDirectory() as tmpdir:
            dbmod.DATABASE_PATH = Path(tmpdir) / "memory_scope.db"
            dbmod.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
            try:
                await dbmod.init_db()

                # Force deterministic heuristic extraction (no model calls).
                mm_mod.MEMORY_ENABLE_NIM_EXTRACTION = False

                mgr = MemoryManager()
                await asyncio.wait_for(
                    mgr.ingest_chat_turn(
                        session_id="s1",
                        user_message="I prefer nmap always for recon.",
                        assistant_message="Use nmap -sV for service detection.",
                        durable_to_global=True,
                    ),
                    timeout=5,
                )

                rows = await dbmod.list_memory_items(session_id=None, limit=500, offset=0)
                # At least one extracted durable fact should be global.
                self.assertTrue(
                    any(r.get("source_type") == "chat" and r.get("memory_type") != "episodic" for r in rows),
                    "expected at least one global durable chat fact",
                )

                session_rows = await dbmod.list_memory_items(session_id="s1", limit=500, offset=0)
                # The episodic snapshot remains session-scoped.
                self.assertTrue(
                    any(r.get("source_type") == "chat" and r.get("memory_type") == "episodic" for r in session_rows),
                    "expected an episodic chat_turn_snapshot stored in session scope",
                )
            finally:
                mm_mod.MEMORY_ENABLE_NIM_EXTRACTION = original_nim_extraction
                dbmod.DATABASE_PATH = original_path

