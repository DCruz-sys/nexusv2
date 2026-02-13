CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS episodic_memory (
    id SERIAL PRIMARY KEY,
    agent_type VARCHAR(100) NOT NULL,
    target VARCHAR(500),
    action TEXT NOT NULL,
    result TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    embedding VECTOR(1536),
    timestamp TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_type ON episodic_memory (agent_type);
CREATE INDEX IF NOT EXISTS idx_timestamp ON episodic_memory (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_episodic_embedding ON episodic_memory USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

CREATE TABLE IF NOT EXISTS semantic_memory (
    id SERIAL PRIMARY KEY,
    category VARCHAR(100) NOT NULL,
    content TEXT NOT NULL,
    metadata JSONB,
    embedding VECTOR(1536),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_category ON semantic_memory (category);
CREATE INDEX IF NOT EXISTS idx_semantic_embedding ON semantic_memory USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

CREATE TABLE IF NOT EXISTS tool_cache (
    id SERIAL PRIMARY KEY,
    tool_name VARCHAR(100) NOT NULL,
    parameters JSONB NOT NULL,
    output TEXT,
    exit_code INTEGER,
    cached_at TIMESTAMP DEFAULT NOW(),
    ttl INTEGER DEFAULT 3600
);
CREATE INDEX IF NOT EXISTS idx_tool_cached ON tool_cache (tool_name, cached_at);

CREATE TABLE IF NOT EXISTS pentest_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target VARCHAR(500) NOT NULL,
    scope JSONB NOT NULL,
    status VARCHAR(50) NOT NULL,
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    results JSONB
);
CREATE INDEX IF NOT EXISTS idx_session_status ON pentest_sessions (status);
CREATE INDEX IF NOT EXISTS idx_session_started ON pentest_sessions (started_at DESC);

CREATE TABLE IF NOT EXISTS procedural_memory (
    id SERIAL PRIMARY KEY,
    agent_type VARCHAR(100) NOT NULL,
    target_profile VARCHAR(255) NOT NULL,
    task_type VARCHAR(100) NOT NULL,
    strategy_hash VARCHAR(64) NOT NULL,
    strategy_template JSONB NOT NULL,
    context_features JSONB,
    version INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    usage_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    reward_sum DOUBLE PRECISION NOT NULL DEFAULT 0,
    avg_reward DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_reward DOUBLE PRECISION,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_procedural_strategy_version
    ON procedural_memory (agent_type, target_profile, task_type, strategy_hash, version);
CREATE INDEX IF NOT EXISTS idx_procedural_lookup
    ON procedural_memory (agent_type, target_profile, task_type, is_active, avg_reward DESC, updated_at DESC);

CREATE TABLE IF NOT EXISTS strategy_outcomes (
    id SERIAL PRIMARY KEY,
    procedural_memory_id INTEGER NOT NULL REFERENCES procedural_memory(id) ON DELETE CASCADE,
    strategy_hash VARCHAR(64) NOT NULL,
    target_profile VARCHAR(255) NOT NULL,
    task_type VARCHAR(100) NOT NULL,
    context_features JSONB,
    reward DOUBLE PRECISION NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    action_sequence JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_strategy_outcome_lookup
    ON strategy_outcomes (strategy_hash, task_type, target_profile, created_at DESC);
