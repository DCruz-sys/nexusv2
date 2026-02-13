-- Nexus v2 initial schema.
-- Local-first, SQLite (WAL) with run/task/event primitives.

PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);

-- Engagements (scope + knowledge + notes container)
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_rules (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    type TEXT NOT NULL, -- domain|ip|cidr
    pattern TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scope_rules_engagement ON scope_rules(engagement_id);

-- Secrets (encrypted at rest; encryption implementation is in app code)
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value_encrypted BLOB NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
    UNIQUE(engagement_id, key)
);

-- Runs
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    kind TEXT NOT NULL, -- scan|swarm|crawl|distill|report|maintenance
    target_json TEXT NOT NULL DEFAULT '{}',
    scan_mode TEXT,
    status TEXT NOT NULL, -- queued|running|stopping|stopped|completed|error
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    error TEXT,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_runs_engagement_created ON runs(engagement_id, created_at);
CREATE INDEX IF NOT EXISTS idx_runs_status_created ON runs(status, created_at);

-- Immutable task graph per run
CREATE TABLE IF NOT EXISTS task_graphs (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    graph_json TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

-- Tasks (worker-claimed)
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL, -- stable id inside graph
    type TEXT NOT NULL, -- tool|llm|browser|kb|control
    status TEXT NOT NULL DEFAULT 'queued', -- queued|running|completed|error|cancelled
    deps_json TEXT NOT NULL DEFAULT '[]',
    spec_json TEXT NOT NULL DEFAULT '{}',
    priority INTEGER NOT NULL DEFAULT 0,
    timeout_sec INTEGER NOT NULL DEFAULT 90,
    attempt INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 1,
    worker_id TEXT,
    lease_until TEXT,
    heartbeat_at TEXT,
    started_at TEXT,
    completed_at TEXT,
    result_json TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(run_id, task_id),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tasks_run_status ON tasks(run_id, status);
CREATE INDEX IF NOT EXISTS idx_tasks_status_priority ON tasks(status, priority);
CREATE INDEX IF NOT EXISTS idx_tasks_lease ON tasks(status, lease_until);

-- Events (append-only per run, with per-run seq)
CREATE TABLE IF NOT EXISTS run_event_counters (
    run_id TEXT PRIMARY KEY,
    next_seq INTEGER NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    redacted_payload_json TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(run_id, seq),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_run_seq ON events(run_id, seq);

-- Artifacts (files on disk, pointers in DB)
CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    task_id TEXT,
    kind TEXT NOT NULL, -- stdout|stderr|report_html|screenshot|http_exchange|log
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    meta_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_artifacts_run ON artifacts(run_id, created_at);

-- HITL
CREATE TABLE IF NOT EXISTS hitl_requests (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    task_id TEXT,
    action TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending|approved|rejected
    decided_by TEXT,
    decided_at TEXT,
    reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_hitl_status_created ON hitl_requests(status, created_at);

-- Findings + evidence
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT,
    severity TEXT,
    state TEXT NOT NULL DEFAULT 'hypothesis', -- hypothesis|needs_validation|confirmed|rejected|inconclusive
    confidence REAL NOT NULL DEFAULT 0.5,
    summary TEXT,
    meta_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_run_state ON findings(run_id, state);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    kind TEXT NOT NULL, -- tool_output|http_exchange|browser_screenshot|script|log
    artifact_id TEXT,
    meta_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id, created_at);

-- Notes / loot
CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    run_id TEXT,
    task_id TEXT,
    kind TEXT NOT NULL DEFAULT 'note',
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_notes_engagement_created ON notes(engagement_id, created_at);

CREATE TABLE IF NOT EXISTS command_log (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    task_id TEXT,
    argv_json TEXT NOT NULL,
    cwd TEXT,
    env_redacted_json TEXT NOT NULL DEFAULT '{}',
    started_at TEXT,
    completed_at TEXT,
    rc INTEGER,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_command_log_run ON command_log(run_id, started_at);

-- Auth API keys (global)
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    key_hash TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

-- Tool capabilities + policy (global)
CREATE TABLE IF NOT EXISTS tool_capabilities (
    id TEXT PRIMARY KEY,
    tool_name TEXT NOT NULL UNIQUE,
    available INTEGER NOT NULL DEFAULT 0,
    checked_at TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS command_policies (
    id TEXT PRIMARY KEY,
    tool_name TEXT NOT NULL UNIQUE,
    allowed_args TEXT NOT NULL DEFAULT '[]',
    blocked_args TEXT NOT NULL DEFAULT '[]',
    hitl_required INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Workers
CREATE TABLE IF NOT EXISTS worker_heartbeats (
    worker_id TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    meta_json TEXT NOT NULL DEFAULT '{}'
);

-- Memory (ported conceptually from v1; implementation can be moved later)
CREATE TABLE IF NOT EXISTS memory_items (
    id TEXT PRIMARY KEY,
    engagement_id TEXT,
    session_id TEXT,
    memory_type TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id TEXT,
    content TEXT NOT NULL,
    summary TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    importance REAL NOT NULL DEFAULT 0.5,
    confidence REAL NOT NULL DEFAULT 0.7,
    recall_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_accessed_at TEXT,
    expires_at TEXT,
    content_hash TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS memory_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_memory_id TEXT NOT NULL,
    to_memory_id TEXT NOT NULL,
    relation TEXT NOT NULL,
    weight REAL NOT NULL DEFAULT 1.0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (from_memory_id) REFERENCES memory_items(id) ON DELETE CASCADE,
    FOREIGN KEY (to_memory_id) REFERENCES memory_items(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS memory_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    session_id TEXT,
    reason TEXT,
    payload TEXT NOT NULL DEFAULT '{}',
    signature TEXT,
    prev_hash TEXT,
    event_hash TEXT,
    created_at TEXT NOT NULL
);

-- Knowledge base (crawler/distill)
CREATE TABLE IF NOT EXISTS kb_documents (
    id TEXT PRIMARY KEY,
    source_url TEXT NOT NULL,
    domain TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    status TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    content_type TEXT,
    content TEXT,
    meta_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(source_url, content_hash)
);

CREATE TABLE IF NOT EXISTS kb_passages (
    id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL,
    source_url TEXT NOT NULL,
    domain TEXT NOT NULL,
    passage_index INTEGER NOT NULL,
    content TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    FOREIGN KEY (document_id) REFERENCES kb_documents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS kb_extractions (
    id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL,
    source_url TEXT NOT NULL,
    fact TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'general',
    confidence REAL NOT NULL DEFAULT 0.5,
    dedupe_hash TEXT UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    FOREIGN KEY (document_id) REFERENCES kb_documents(id) ON DELETE CASCADE
);
