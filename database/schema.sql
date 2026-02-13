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
