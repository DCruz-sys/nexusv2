import hashlib
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import importlib

import redis.asyncio as redis
from loguru import logger


def _optional_import(module_name: str):
    try:
        return importlib.import_module(module_name)
    except ModuleNotFoundError:
        return None


asyncpg = _optional_import('asyncpg')
_register_mod = _optional_import('pgvector.asyncpg')
register_vector = getattr(_register_mod, 'register_vector', None)


class MemorySystem:
    def __init__(self, nim_provider: Any):
        self.nim = nim_provider
        self.db_pool: Optional[Any] = None
        self.redis_client: Optional[redis.Redis] = None
        self.enabled = True

    async def initialize(self) -> None:
        if asyncpg is None:
            self.enabled = False
            logger.warning("asyncpg is not installed; memory DB features disabled. Install requirements-postgres.txt to enable.")
            return

        self.db_pool = await asyncpg.create_pool(
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=int(os.getenv("POSTGRES_PORT", "5432")),
            database=os.getenv("POSTGRES_DB", "nexus_memory"),
            user=os.getenv("POSTGRES_USER", "nexus"),
            password=os.getenv("POSTGRES_PASSWORD", "nexus"),
            min_size=1,
            max_size=5,
        )
        if register_vector is not None:
            await register_vector(self.db_pool)
        self.redis_client = redis.from_url(
            f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}",
            encoding="utf-8",
            decode_responses=True,
        )
        logger.info("Memory system initialized")

    async def store_episodic(self, agent_type: str, task: Dict[str, Any], action_plan: Dict[str, Any], results: Dict[str, Any], success: bool) -> int:
        if not self.db_pool:
            return -1
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
        if not self.db_pool:
            return []
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
        if not self.db_pool:
            return -1
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
        if not self.db_pool:
            return []
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

    async def store_procedural_memory(
        self,
        agent_type: str,
        target_profile: str,
        task_type: str,
        strategy_template: Dict[str, Any],
        context_features: Optional[Dict[str, Any]] = None,
    ) -> int:
        if not self.db_pool:
            return -1
        strategy_hash = hashlib.sha256(json.dumps(strategy_template, sort_keys=True).encode()).hexdigest()
        context_features = context_features or {}
        async with self.db_pool.acquire() as conn:
            existing = await conn.fetchrow(
                """
                SELECT id, version FROM procedural_memory
                WHERE agent_type=$1 AND target_profile=$2 AND task_type=$3 AND strategy_hash=$4 AND is_active=TRUE
                ORDER BY version DESC
                LIMIT 1
                """,
                agent_type,
                target_profile,
                task_type,
                strategy_hash,
            )
            if existing:
                await conn.execute(
                    """
                    UPDATE procedural_memory
                    SET strategy_template=$1, context_features=$2, updated_at=$3
                    WHERE id=$4
                    """,
                    json.dumps(strategy_template),
                    json.dumps(context_features),
                    datetime.now(),
                    existing["id"],
                )
                return existing["id"]

            version = await conn.fetchval(
                """
                SELECT COALESCE(MAX(version), 0) + 1
                FROM procedural_memory
                WHERE agent_type=$1 AND target_profile=$2 AND task_type=$3
                """,
                agent_type,
                target_profile,
                task_type,
            )

            return await conn.fetchval(
                """
                INSERT INTO procedural_memory
                (agent_type, target_profile, task_type, strategy_hash, strategy_template, context_features, version)
                VALUES ($1,$2,$3,$4,$5,$6,$7)
                RETURNING id
                """,
                agent_type,
                target_profile,
                task_type,
                strategy_hash,
                json.dumps(strategy_template),
                json.dumps(context_features),
                version,
            )

    async def record_strategy_outcome(
        self,
        strategy_id: int,
        strategy_hash: str,
        target_profile: str,
        task_type: str,
        reward: float,
        outcome: str,
        action_sequence: Optional[List[Dict[str, Any]]] = None,
        context_features: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not self.db_pool:
            return
        context_features = context_features or {}
        action_sequence = action_sequence or []

        async with self.db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO strategy_outcomes
                (procedural_memory_id, strategy_hash, target_profile, task_type, context_features, reward, outcome, action_sequence)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                """,
                strategy_id,
                strategy_hash,
                target_profile,
                task_type,
                json.dumps(context_features),
                reward,
                outcome,
                json.dumps(action_sequence),
            )

            await conn.execute(
                """
                UPDATE procedural_memory
                SET
                    usage_count = usage_count + 1,
                    success_count = success_count + CASE WHEN $2 = 'success' THEN 1 ELSE 0 END,
                    failure_count = failure_count + CASE WHEN $2 != 'success' THEN 1 ELSE 0 END,
                    reward_sum = reward_sum + $1,
                    avg_reward = (reward_sum + $1) / NULLIF(usage_count + 1, 0),
                    last_reward = $1,
                    last_used_at = $3,
                    updated_at = $3
                WHERE id = $4
                """,
                reward,
                outcome,
                datetime.now(),
                strategy_id,
            )

    async def query_procedural_memory(
        self,
        agent_type: str,
        target_profile: str,
        task_type: str,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        if not self.db_pool:
            return []
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, agent_type, target_profile, task_type, strategy_hash, strategy_template,
                       context_features, version, usage_count, success_count, failure_count,
                       avg_reward, last_reward, last_used_at, updated_at
                FROM procedural_memory
                WHERE agent_type=$1
                  AND target_profile=$2
                  AND task_type=$3
                  AND is_active=TRUE
                ORDER BY avg_reward DESC, success_count DESC, updated_at DESC
                LIMIT $4
                """,
                agent_type,
                target_profile,
                task_type,
                limit,
            )
        return [dict(r) for r in rows]

    async def prune_procedural_memory(self, max_versions: int = 3, stale_days: int = 30) -> None:
        if not self.db_pool:
            return
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE procedural_memory pm
                SET is_active = FALSE, updated_at = $1
                WHERE id IN (
                    SELECT id FROM (
                        SELECT id,
                               ROW_NUMBER() OVER (
                                   PARTITION BY agent_type, target_profile, task_type
                                   ORDER BY version DESC
                               ) AS version_rank
                        FROM procedural_memory
                        WHERE is_active = TRUE
                    ) ranked
                    WHERE version_rank > $2
                )
                """,
                datetime.now(),
                max_versions,
            )

            await conn.execute(
                """
                UPDATE procedural_memory
                SET is_active = FALSE, updated_at = $1
                WHERE is_active = TRUE
                  AND COALESCE(last_used_at, created_at) < (NOW() - ($2::text || ' days')::interval)
                  AND avg_reward <= 0
                """,
                datetime.now(),
                stale_days,
            )

    async def close(self) -> None:
        if self.db_pool:
            await self.db_pool.close()
        if self.redis_client:
            await self.redis_client.close()
