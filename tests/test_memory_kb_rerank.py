import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import app.ai.memory_manager as mm_mod
import app.database as dbmod
from app.ai.memory_manager import MemoryManager


class MemoryKBRerankTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db = dbmod.DATABASE_PATH
        dbmod.DATABASE_PATH = Path(self._tmpdir.name) / "test.db"
        dbmod.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        await dbmod.init_db()

        self._orig_rerank_enabled = mm_mod.KB_RERANK_ENABLED
        self._orig_retrieval_limit = mm_mod.KB_RETRIEVAL_LIMIT
        self._orig_candidate_limit = mm_mod.KB_RETRIEVAL_CANDIDATES
        mm_mod.KB_RERANK_ENABLED = True
        mm_mod.KB_RETRIEVAL_LIMIT = 2
        mm_mod.KB_RETRIEVAL_CANDIDATES = 5

    async def asyncTearDown(self):
        mm_mod.KB_RERANK_ENABLED = self._orig_rerank_enabled
        mm_mod.KB_RETRIEVAL_LIMIT = self._orig_retrieval_limit
        mm_mod.KB_RETRIEVAL_CANDIDATES = self._orig_candidate_limit
        dbmod.DATABASE_PATH = self._original_db
        self._tmpdir.cleanup()

    async def test_kb_rerank_order_applied(self):
        source_id = await dbmod.upsert_crawl_source("example.com", "https://example.com", trust_score=0.9)
        content = "cve guidance page"
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        doc_id, inserted = await dbmod.add_crawl_document(
            source_id=source_id,
            url="https://example.com/advisory",
            domain="example.com",
            depth=0,
            status="ok",
            content_hash=content_hash,
            content_type="text/html",
            content=content,
            lang="en",
            source_trust=0.9,
            expires_at=None,
        )
        self.assertTrue(inserted)

        first = "CVE analysis baseline and remediation checklist."
        second = "CVE exploitability priority matrix for patch planning."
        inserted_count = await dbmod.add_crawl_passages_bulk(
            document_id=doc_id,
            source_url="https://example.com/advisory",
            domain="example.com",
            depth=0,
            passages=[first, second],
            expires_at=None,
        )
        self.assertGreaterEqual(inserted_count, 2)

        mgr = MemoryManager()
        with patch.object(mm_mod.nim_retrieval_client, "rerank", new=AsyncMock(return_value=[1, 0])):
            bundle = await mgr.retrieve_context(session_id="s1", query="cve", limit=2)

        kb_items = bundle.get("kb_items") or []
        self.assertGreaterEqual(len(kb_items), 2)
        self.assertIn("priority matrix", str(kb_items[0].get("content") or "").lower())
