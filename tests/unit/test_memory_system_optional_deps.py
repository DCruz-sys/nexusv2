import asyncio

from core import memory_system as ms
from core.memory_system import MemorySystem


class DummyNIM:
    async def get_embedding(self, _: str):
        return [0.0]


def test_memory_system_initializes_without_asyncpg(monkeypatch):
    async def _run():
        monkeypatch.setattr(ms, "asyncpg", None)
        memory = MemorySystem(DummyNIM())
        await memory.initialize()
        assert memory.enabled is False
        assert memory.db_pool is None

    asyncio.run(_run())


def test_memory_methods_noop_without_db_pool():
    async def _run():
        memory = MemorySystem(DummyNIM())
        assert await memory.store_episodic("recon", {}, {}, {}, True) == -1
        assert await memory.query_episodic("test") == []
        assert await memory.store_semantic("cat", "content", {}) == -1
        assert await memory.query_semantic("test") == []

    asyncio.run(_run())
