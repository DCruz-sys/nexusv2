import hashlib
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import asyncpg
import redis.asyncio as redis
from loguru import logger
from pgvector.asyncpg import register_vector


class MemorySystem:
    def __init__(self, nim_provider: Any):
        self.nim = nim_provider
        self.db_pool: Optional[asyncpg.Pool] = None
        self.redis_client: Optional[redis.Redis] = None

    async def initialize(self) -> None:
        self.db_pool = await asyncpg.create_pool(
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=int(os.getenv("POSTGRES_PORT", "5432")),
            database=os.getenv("POSTGRES_DB", "nexus_memory"),
            user=os.getenv("POSTGRES_USER", "nexus"),
            password=os.getenv("POSTGRES_PASSWORD", "nexus"),
            min_size=1,
            max_size=5,
        )
        await register_vector(self.db_pool)
        self.redis_client = redis.from_url(
            f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}",
            encoding="utf-8",
            decode_responses=True,
        )
        logger.info("Memory system initialized")

    async def store_episodic(self, agent_type: str, task: Dict[str, Any], action_plan: Dict[str, Any], results: Dict[str, Any], success: bool) -> int:
        episode_text = f"Agent:{agent_type} Task:{task.get('description','')} Success:{success}"
        embedding = await self.nim.get_embedding(episode_text)
        async with self.db_pool.acquire() as conn:
            return await conn.fetchval(
                """
                INSERT INTO episodic_memory (agent_type, target, action, result, success, embedding, timestamp)
                VALUES ($1,$2,$3,$4,$5,$6,$7)
                RETURNING id
                """,
                agent_type,
                task.get("target", "unknown"),
                json.dumps(action_plan),
                json.dumps(results),
                success,
                embedding,
                datetime.now(),
            )

    async def query_episodic(self, query_text: str, agent_type: Optional[str] = None, limit: int = 5) -> List[Dict[str, Any]]:
        cache_key = f"episodic:{hashlib.md5((query_text+str(agent_type)+str(limit)).encode()).hexdigest()}"
        if self.redis_client:
            cached = await self.redis_client.get(cache_key)
            if cached:
                return json.loads(cached)
        query_embedding = await self.nim.get_embedding(query_text)
        async with self.db_pool.acquire() as conn:
            if agent_type:
                rows = await conn.fetch(
                    "SELECT id,agent_type,target,action,result,success,timestamp,1-(embedding<=>$1) similarity FROM episodic_memory WHERE agent_type=$2 ORDER BY embedding<=>$1 LIMIT $3",
                    query_embedding,
                    agent_type,
                    limit,
                )
            else:
                rows = await conn.fetch(
                    "SELECT id,agent_type,target,action,result,success,timestamp,1-(embedding<=>$1) similarity FROM episodic_memory ORDER BY embedding<=>$1 LIMIT $2",
                    query_embedding,
                    limit,
                )
        data = [dict(r) for r in rows]
        if self.redis_client:
            await self.redis_client.setex(cache_key, 3600, json.dumps(data, default=str))
        return data

    async def store_semantic(self, category: str, content: str, metadata: Dict[str, Any]) -> int:
        embedding = await self.nim.get_embedding(content)
        async with self.db_pool.acquire() as conn:
            return await conn.fetchval(
                "INSERT INTO semantic_memory (category, content, metadata, embedding) VALUES ($1,$2,$3,$4) RETURNING id",
                category,
                content,
                json.dumps(metadata),
                embedding,
            )

    async def query_semantic(self, query_text: str, category: Optional[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
        query_embedding = await self.nim.get_embedding(query_text)
        async with self.db_pool.acquire() as conn:
            if category:
                rows = await conn.fetch(
                    "SELECT id,category,content,metadata,1-(embedding<=>$1) similarity FROM semantic_memory WHERE category=$2 ORDER BY embedding<=>$1 LIMIT $3",
                    query_embedding,
                    category,
                    limit,
                )
            else:
                rows = await conn.fetch(
                    "SELECT id,category,content,metadata,1-(embedding<=>$1) similarity FROM semantic_memory ORDER BY embedding<=>$1 LIMIT $2",
                    query_embedding,
                    limit,
                )
        return [dict(r) for r in rows]

    async def close(self) -> None:
        if self.db_pool:
            await self.db_pool.close()
        if self.redis_client:
            await self.redis_client.close()
