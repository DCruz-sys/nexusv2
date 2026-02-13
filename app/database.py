"""SQLite database setup and CRUD operations."""
import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import aiosqlite

from app.config import (
    DATABASE_PATH,
    JOB_LEASE_SECONDS,
    SQLITE_BUSY_TIMEOUT_MS,
    SQLITE_RETRY_ATTEMPTS,
    SQLITE_RETRY_BACKOFF_MS,
)
from app.observability.context import get_correlation_id

DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _utcnow().isoformat()


def _json_dumps(value: Any) -> str:
    return json.dumps(value if value is not None else {}, default=str)


def _audit_event_hash(
    *,
    event_type: str,
    actor: str,
    session_id: Optional[str],
    reason: Optional[str],
    payload_json: str,
    signature: Optional[str],
    created_at: str,
    prev_hash: Optional[str],
) -> str:
    canonical = {
        "event_type": event_type or "",
        "actor": actor or "",
        "session_id": session_id or "",
        "reason": reason or "",
        "payload": payload_json or "{}",
        "signature": signature or "",
        "created_at": created_at or "",
        "prev_hash": prev_hash or "",
    }
    material = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


async def get_db():
    """Get database connection."""
    db = await aiosqlite.connect(str(DATABASE_PATH))
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL;")
    await db.execute("PRAGMA synchronous=NORMAL;")
    await db.execute("PRAGMA foreign_keys=ON;")
    await db.execute(f"PRAGMA busy_timeout={max(100, SQLITE_BUSY_TIMEOUT_MS)};")
    return db


def _is_locked_error(exc: Exception) -> bool:
    return "locked" in str(exc).lower() or "busy" in str(exc).lower()


async def _with_retry(coro_factory, attempts: int = SQLITE_RETRY_ATTEMPTS):
    retry_count = max(1, int(attempts))
    for idx in range(retry_count):
        try:
            return await coro_factory()
        except aiosqlite.OperationalError as exc:
            if not _is_locked_error(exc) or idx >= retry_count - 1:
                raise
            await asyncio.sleep((SQLITE_RETRY_BACKOFF_MS / 1000.0) * (idx + 1))


async def init_db():
    """Initialize database tables."""
    db = await get_db()
    try:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                scan_type TEXT DEFAULT 'full',
                methodology TEXT DEFAULT 'owasp',
                status TEXT DEFAULT 'pending',
                progress INTEGER DEFAULT 0,
                config TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT,
                completed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                phase TEXT,
                tool_name TEXT,
                command TEXT,
                output TEXT,
                findings TEXT DEFAULT '[]',
                severity TEXT DEFAULT 'info',
                status TEXT DEFAULT 'pending',
                started_at TEXT,
                completed_at TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS chat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                model_used TEXT,
                task_type TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                format TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS memory_items (
                id TEXT PRIMARY KEY,
                session_id TEXT,
                memory_type TEXT NOT NULL,
                source_type TEXT NOT NULL,
                source_id TEXT,
                content TEXT NOT NULL,
                summary TEXT,
                metadata TEXT DEFAULT '{}',
                importance REAL DEFAULT 0.5,
                confidence REAL DEFAULT 0.7,
                recall_count INTEGER DEFAULT 0,
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
                weight REAL DEFAULT 1.0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (from_memory_id) REFERENCES memory_items(id),
                FOREIGN KEY (to_memory_id) REFERENCES memory_items(id)
            );

            CREATE TABLE IF NOT EXISTS memory_checkpoints (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                checkpoint_type TEXT NOT NULL,
                state_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS memory_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                session_id TEXT,
                reason TEXT,
                payload TEXT DEFAULT '{}',
                signature TEXT,
                prev_hash TEXT,
                event_hash TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS schema_migrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS target_allowlist (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                pattern TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                created_by TEXT DEFAULT 'system',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS job_queue (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                attempt INTEGER DEFAULT 0,
                max_attempts INTEGER DEFAULT 3,
                next_run_at TEXT NOT NULL,
                error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                worker_id TEXT,
                lease_until TEXT,
                heartbeat_at TEXT
            );

            CREATE TABLE IF NOT EXISTS worker_heartbeats (
                worker_id TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                meta TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS crawl_sources (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                source_url TEXT NOT NULL,
                trust_score REAL DEFAULT 0.5,
                status TEXT DEFAULT 'active',
                last_crawled_at TEXT,
                pages_crawled INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS crawl_documents (
                id TEXT PRIMARY KEY,
                source_id TEXT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                depth INTEGER DEFAULT 0,
                fetched_at TEXT NOT NULL,
                status TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                content_type TEXT,
                content TEXT,
                lang TEXT,
                source_trust REAL DEFAULT 0.5,
                expires_at TEXT,
                UNIQUE(url, content_hash),
                FOREIGN KEY (source_id) REFERENCES crawl_sources(id)
            );

            CREATE TABLE IF NOT EXISTS crawl_extractions (
                id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL,
                source_url TEXT NOT NULL,
                fact TEXT NOT NULL,
                category TEXT DEFAULT 'general',
                confidence REAL DEFAULT 0.5,
                dedupe_hash TEXT UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                FOREIGN KEY (document_id) REFERENCES crawl_documents(id)
            );

            CREATE TABLE IF NOT EXISTS crawl_passages (
                id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL,
                source_url TEXT NOT NULL,
                domain TEXT NOT NULL,
                depth INTEGER DEFAULT 0,
                passage_index INTEGER NOT NULL,
                content TEXT NOT NULL,
                content_hash TEXT UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                FOREIGN KEY (document_id) REFERENCES crawl_documents(id)
            );

            CREATE TABLE IF NOT EXISTS learning_runs (
                run_id TEXT PRIMARY KEY,
                stage TEXT NOT NULL,
                status TEXT NOT NULL,
                metrics TEXT DEFAULT '{}',
                started_at TEXT NOT NULL,
                finished_at TEXT
            );

            CREATE TABLE IF NOT EXISTS learning_sources (
                id TEXT PRIMARY KEY,
                seed_url TEXT NOT NULL UNIQUE,
                domain TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                profile TEXT DEFAULT 'aggressive_deep',
                max_depth INTEGER DEFAULT 6,
                max_pages_per_domain INTEGER DEFAULT 300,
                max_pages_per_day INTEGER DEFAULT 2500,
                allow_subdomains INTEGER DEFAULT 1,
                recrawl_interval_min INTEGER DEFAULT 360,
                last_run_at TEXT,
                next_run_at TEXT,
                consecutive_failures INTEGER DEFAULT 0,
                metadata TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS learning_frontier (
                id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                depth INTEGER DEFAULT 0,
                priority INTEGER DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'queued',
                discovered_from TEXT,
                last_error TEXT,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                next_retry_at TEXT,
                UNIQUE(source_id, url),
                FOREIGN KEY (source_id) REFERENCES learning_sources(id)
            );

            CREATE TABLE IF NOT EXISTS learning_checkpoints (
                id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL UNIQUE,
                checkpoint_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (source_id) REFERENCES learning_sources(id)
            );

            CREATE TABLE IF NOT EXISTS learning_source_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY (source_id) REFERENCES learning_sources(id)
            );

            CREATE TABLE IF NOT EXISTS tool_capabilities (
                id TEXT PRIMARY KEY,
                tool_name TEXT NOT NULL UNIQUE,
                available INTEGER DEFAULT 0,
                checked_at TEXT NOT NULL,
                details TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                key_hash TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL,
                scopes TEXT DEFAULT '[]',
                created_at TEXT NOT NULL,
                revoked_at TEXT
            );

            CREATE TABLE IF NOT EXISTS swarm_runs (
                run_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                objective TEXT NOT NULL,
                methodology TEXT DEFAULT 'owasp',
                scan_type TEXT DEFAULT 'quick',
                config TEXT DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'queued',
                error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS swarm_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                agent TEXT NOT NULL,
                task TEXT NOT NULL,
                dependencies TEXT DEFAULT '[]',
                priority INTEGER DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'queued',
                attempt INTEGER DEFAULT 0,
                max_attempts INTEGER DEFAULT 1,
                timeout_sec INTEGER DEFAULT 90,
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                UNIQUE(run_id, task_id),
                FOREIGN KEY (run_id) REFERENCES swarm_runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS swarm_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES swarm_runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS crawler_policy (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL UNIQUE,
                allow INTEGER DEFAULT 1,
                max_depth INTEGER,
                daily_cap INTEGER,
                trust_floor REAL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS command_policy (
                id TEXT PRIMARY KEY,
                tool_name TEXT NOT NULL UNIQUE,
                allowed_args TEXT DEFAULT '[]',
                blocked_args TEXT DEFAULT '[]',
                hitl_required INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scans_created_at
                ON scans(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id
                ON scan_results(scan_id);
            CREATE INDEX IF NOT EXISTS idx_chat_history_session_created
                ON chat_history(session_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_reports_scan_created
                ON reports(scan_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_memory_session_created
                ON memory_items(session_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_memory_importance
                ON memory_items(importance DESC, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_memory_source
                ON memory_items(source_type, source_id);
            CREATE INDEX IF NOT EXISTS idx_memory_expires
                ON memory_items(expires_at);
            CREATE INDEX IF NOT EXISTS idx_memory_checkpoints_session
                ON memory_checkpoints(session_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_memory_audit_created
                ON memory_audit_log(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_target_allowlist_pattern
                ON target_allowlist(pattern, enabled);
            CREATE INDEX IF NOT EXISTS idx_job_queue_status_run
                ON job_queue(status, next_run_at, type);
            CREATE INDEX IF NOT EXISTS idx_worker_heartbeats_role_updated
                ON worker_heartbeats(role, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_crawl_sources_domain
                ON crawl_sources(domain, status);
            CREATE INDEX IF NOT EXISTS idx_crawl_documents_domain_fetched
                ON crawl_documents(domain, fetched_at DESC);
            CREATE INDEX IF NOT EXISTS idx_crawl_extractions_created
                ON crawl_extractions(created_at DESC, category);
            CREATE INDEX IF NOT EXISTS idx_crawl_passages_domain_created
                ON crawl_passages(domain, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_crawl_passages_document
                ON crawl_passages(document_id, passage_index);
            CREATE INDEX IF NOT EXISTS idx_crawl_passages_created
                ON crawl_passages(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_learning_runs_stage
                ON learning_runs(stage, started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_learning_sources_enabled_next
                ON learning_sources(enabled, next_run_at);
            CREATE INDEX IF NOT EXISTS idx_learning_frontier_status_retry
                ON learning_frontier(source_id, status, next_retry_at, priority DESC, last_seen_at ASC);
            CREATE INDEX IF NOT EXISTS idx_learning_frontier_domain
                ON learning_frontier(domain, status);
            CREATE INDEX IF NOT EXISTS idx_learning_source_events_source
                ON learning_source_events(source_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_tool_capabilities_checked
                ON tool_capabilities(checked_at DESC);
            CREATE INDEX IF NOT EXISTS idx_api_keys_name
                ON api_keys(name);
            CREATE INDEX IF NOT EXISTS idx_api_keys_revoked
                ON api_keys(revoked_at);
            CREATE INDEX IF NOT EXISTS idx_swarm_runs_created
                ON swarm_runs(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_swarm_runs_status
                ON swarm_runs(status, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_swarm_tasks_run
                ON swarm_tasks(run_id, status, priority DESC, id ASC);
            CREATE INDEX IF NOT EXISTS idx_swarm_events_run
                ON swarm_events(run_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_crawler_policy_domain
                ON crawler_policy(domain);
            CREATE INDEX IF NOT EXISTS idx_command_policy_tool
                ON command_policy(tool_name);
        """)
        # Idempotent schema upgrades for existing databases.
        for alter_sql in (
            "ALTER TABLE job_queue ADD COLUMN worker_id TEXT",
            "ALTER TABLE job_queue ADD COLUMN lease_until TEXT",
            "ALTER TABLE job_queue ADD COLUMN heartbeat_at TEXT",
            "ALTER TABLE memory_audit_log ADD COLUMN prev_hash TEXT",
            "ALTER TABLE memory_audit_log ADD COLUMN event_hash TEXT",
        ):
            try:
                await db.execute(alter_sql)
            except aiosqlite.OperationalError:
                pass
        try:
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_memory_audit_hash ON memory_audit_log(event_hash)"
            )
        except aiosqlite.OperationalError:
            pass

        # Best-effort full-text index for deep crawl retention (SQLite FTS5).
        # If FTS is unavailable in the runtime SQLite build, we fall back to recency/LIKE queries.
        fts_available = False
        try:
            await db.execute(
                """CREATE VIRTUAL TABLE IF NOT EXISTS crawl_passages_fts
                   USING fts5(
                     content,
                     passage_id UNINDEXED,
                     source_url UNINDEXED,
                     domain UNINDEXED,
                     tokenize='porter'
                   )"""
            )
            fts_available = True
        except aiosqlite.OperationalError:
            fts_available = False

        if fts_available:
            # Backfill index once if empty (covers existing DB upgrades).
            try:
                cursor = await db.execute("SELECT COUNT(*) AS c FROM crawl_passages_fts")
                fts_count = int((await cursor.fetchone())["c"] or 0)
            except Exception:
                fts_count = 0
            if fts_count == 0:
                try:
                    await db.execute(
                        """INSERT INTO crawl_passages_fts (content, passage_id, source_url, domain)
                           SELECT content, id, source_url, domain FROM crawl_passages"""
                    )
                except Exception:
                    # Never block startup on FTS backfill failures.
                    pass

        # Seed minimal policy rows when absent.
        now = _utcnow_iso()
        await db.execute(
            """INSERT OR IGNORE INTO crawler_policy
               (id, domain, allow, max_depth, daily_cap, trust_floor, created_at, updated_at)
               VALUES (?, '*', 1, NULL, NULL, NULL, ?, ?)""",
            (str(uuid.uuid4()), now, now),
        )
        for tool_name, blocked_args, hitl_required in (
            ("sqlmap", ["--os-shell", "--sql-shell", "--file-write", "--file-read"], 1),
            ("msfconsole", [], 1),
            ("hydra", [], 1),
            ("metasploit", [], 1),
        ):
            await db.execute(
                """INSERT OR IGNORE INTO command_policy
                   (id, tool_name, allowed_args, blocked_args, hitl_required, created_at, updated_at)
                   VALUES (?, ?, '[]', ?, ?, ?, ?)""",
                (str(uuid.uuid4()), tool_name, _json_dumps(blocked_args), hitl_required, now, now),
            )
        await db.commit()
    finally:
        await db.close()


# --- Scan CRUD ---


async def create_scan(scan_id: str, target: str, scan_type: str = "full",
                      methodology: str = "owasp", config: dict = None):
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO scans (id, target, scan_type, methodology, config, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, target, scan_type, methodology, _json_dumps(config or {}), _utcnow_iso())
        )
        await db.commit()
    finally:
        await db.close()


async def update_scan(scan_id: str, **kwargs):
    db = await get_db()
    try:
        sets = []
        values = []
        for k, v in kwargs.items():
            sets.append(f"{k} = ?")
            values.append(v)
        sets.append("updated_at = ?")
        values.append(_utcnow_iso())
        values.append(scan_id)
        await db.execute(f"UPDATE scans SET {', '.join(sets)} WHERE id = ?", values)
        await db.commit()
    finally:
        await db.close()


async def get_scan(scan_id: str):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def list_scans(limit: int = 50, offset: int = 0):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, max(0, offset)),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


# --- Scan Results CRUD ---


async def add_scan_result(scan_id: str, phase: str, tool_name: str, command: str,
                          output: str = "", findings: list = None, severity: str = "info",
                          status: str = "completed"):
    db = await get_db()
    try:
        now = _utcnow_iso()
        await db.execute(
            """INSERT INTO scan_results (scan_id, phase, tool_name, command, output, findings, severity, status, started_at, completed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, phase, tool_name, command, output, _json_dumps(findings or []), severity, status, now, now)
        )
        await db.commit()
    finally:
        await db.close()


async def get_scan_results(scan_id: str):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM scan_results WHERE scan_id = ? ORDER BY id", (scan_id,))
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


# --- Chat History CRUD ---


async def save_chat_message(session_id: str, role: str, content: str,
                            model_used: str = None, task_type: str = None):
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO chat_history (session_id, role, content, model_used, task_type, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, role, content, model_used, task_type, _utcnow_iso())
        )
        await db.commit()
    finally:
        await db.close()


async def get_chat_history(session_id: str, limit: int = 50):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM chat_history WHERE session_id = ? ORDER BY created_at DESC LIMIT ?",
            (session_id, limit)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in reversed(rows)]
    finally:
        await db.close()


# --- Reports CRUD ---


async def save_report(report_id: str, scan_id: str, fmt: str, filename: str, file_path: str):
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO reports (id, scan_id, format, filename, file_path, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (report_id, scan_id, fmt, filename, file_path, _utcnow_iso())
        )
        await db.commit()
    finally:
        await db.close()


async def get_reports(scan_id: str = None):
    db = await get_db()
    try:
        if scan_id:
            cursor = await db.execute("SELECT * FROM reports WHERE scan_id = ? ORDER BY created_at DESC", (scan_id,))
        else:
            cursor = await db.execute("SELECT * FROM reports ORDER BY created_at DESC")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


# --- Memory CRUD ---


async def add_memory_item(
    content: str,
    memory_type: str,
    source_type: str,
    session_id: Optional[str] = None,
    source_id: Optional[str] = None,
    summary: Optional[str] = None,
    metadata: Optional[dict] = None,
    importance: float = 0.5,
    confidence: float = 0.7,
    expires_at: Optional[str] = None,
) -> tuple[Optional[str], bool]:
    """Insert long-term memory item or upsert when duplicate content hash exists."""
    normalized_content = " ".join((content or "").strip().lower().split())
    if not normalized_content:
        return None, False

    hash_scope = session_id or "global"
    content_hash = hashlib.sha256(f"{hash_scope}:{normalized_content}".encode("utf-8")).hexdigest()
    db = await get_db()
    try:
        now = _utcnow_iso()
        cursor = await db.execute(
            "SELECT id, importance, confidence, metadata FROM memory_items WHERE content_hash = ?",
            (content_hash,)
        )
        existing = await cursor.fetchone()
        if existing:
            existing_metadata = {}
            try:
                parsed = json.loads(existing["metadata"] or "{}")
                if isinstance(parsed, dict):
                    existing_metadata = parsed
            except Exception:
                pass
            merged_metadata = {**existing_metadata, **(metadata or {})}
            await db.execute(
                """UPDATE memory_items
                   SET importance = ?, confidence = ?, metadata = ?, last_accessed_at = ?, expires_at = ?
                   WHERE id = ?""",
                (
                    max(float(existing["importance"] or 0.0), float(importance)),
                    max(float(existing["confidence"] or 0.0), float(confidence)),
                    _json_dumps(merged_metadata),
                    now,
                    expires_at,
                    existing["id"],
                )
            )
            await db.commit()
            return str(existing["id"]), False

        memory_id = str(uuid.uuid4())
        await db.execute(
            """INSERT INTO memory_items
               (id, session_id, memory_type, source_type, source_id, content, summary, metadata,
                importance, confidence, recall_count, created_at, last_accessed_at, expires_at, content_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, NULL, ?, ?)""",
            (
                memory_id,
                session_id,
                memory_type,
                source_type,
                source_id,
                content.strip(),
                summary,
                _json_dumps(metadata or {}),
                float(importance),
                float(confidence),
                now,
                expires_at,
                content_hash,
            )
        )
        await db.commit()
        return memory_id, True
    finally:
        await db.close()


async def list_memory_items(session_id: Optional[str] = None, limit: int = 100, offset: int = 0):
    db = await get_db()
    try:
        if session_id:
            cursor = await db.execute(
                "SELECT * FROM memory_items WHERE session_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (session_id, limit, offset)
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM memory_items ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_memory_candidates(session_id: Optional[str], limit: int = 250):
    """Return mixed recency + high-importance candidate set for scoring."""
    db = await get_db()
    try:
        where = "(? IS NULL OR session_id = ? OR session_id IS NULL)"
        recency_query = f"""
            SELECT * FROM memory_items
            WHERE {where}
            AND (expires_at IS NULL OR expires_at > ?)
            ORDER BY created_at DESC
            LIMIT ?
        """
        importance_query = f"""
            SELECT * FROM memory_items
            WHERE {where}
            AND (expires_at IS NULL OR expires_at > ?)
            ORDER BY importance DESC, created_at DESC
            LIMIT ?
        """
        now = _utcnow_iso()
        recency_cursor = await db.execute(recency_query, (session_id, session_id, now, limit))
        recency_rows = [dict(r) for r in await recency_cursor.fetchall()]
        importance_cursor = await db.execute(importance_query, (session_id, session_id, now, limit))
        importance_rows = [dict(r) for r in await importance_cursor.fetchall()]
        merged: dict[str, dict] = {}
        for row in recency_rows + importance_rows:
            merged[row["id"]] = row
        return list(merged.values())
    finally:
        await db.close()


async def increment_memory_recall(memory_ids: list[str]):
    if not memory_ids:
        return
    db = await get_db()
    try:
        now = _utcnow_iso()
        await db.executemany(
            """UPDATE memory_items
               SET recall_count = recall_count + 1, last_accessed_at = ?
               WHERE id = ?""",
            [(now, memory_id) for memory_id in memory_ids]
        )
        await db.commit()
    finally:
        await db.close()


async def delete_memory_items(memory_ids: list[str]) -> int:
    if not memory_ids:
        return 0
    db = await get_db()
    try:
        cursor = await db.executemany(
            "DELETE FROM memory_items WHERE id = ?",
            [(memory_id,) for memory_id in memory_ids]
        )
        await db.commit()
        return cursor.rowcount if cursor else 0
    finally:
        await db.close()


async def add_memory_edge(from_memory_id: str, to_memory_id: str, relation: str, weight: float = 1.0):
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO memory_edges (from_memory_id, to_memory_id, relation, weight, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (from_memory_id, to_memory_id, relation, float(weight), _utcnow_iso())
        )
        await db.commit()
    finally:
        await db.close()


async def get_memory_edges(memory_id: str):
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM memory_edges
               WHERE from_memory_id = ? OR to_memory_id = ?
               ORDER BY created_at DESC""",
            (memory_id, memory_id)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def save_memory_checkpoint(session_id: str, checkpoint_type: str, state: dict) -> str:
    checkpoint_id = str(uuid.uuid4())
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO memory_checkpoints (id, session_id, checkpoint_type, state_json, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (checkpoint_id, session_id, checkpoint_type, _json_dumps(state or {}), _utcnow_iso())
        )
        await db.commit()
        return checkpoint_id
    finally:
        await db.close()


async def get_memory_checkpoints(session_id: str, limit: int = 50):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM memory_checkpoints WHERE session_id = ? ORDER BY created_at DESC LIMIT ?",
            (session_id, limit)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_memory_checkpoint(checkpoint_id: str):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM memory_checkpoints WHERE id = ?",
            (checkpoint_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def add_memory_audit_event(
    event_type: str,
    actor: str,
    session_id: Optional[str] = None,
    reason: Optional[str] = None,
    payload: Optional[dict] = None,
    signature: Optional[str] = None,
):
    db = await get_db()
    try:
        payload_obj = dict(payload or {})
        correlation_id = get_correlation_id()
        if correlation_id and "correlation_id" not in payload_obj:
            payload_obj["correlation_id"] = correlation_id
        payload_json = _json_dumps(payload_obj)
        created_at = _utcnow_iso()
        previous_hash = ""
        prev_cursor = await db.execute(
            "SELECT event_hash FROM memory_audit_log ORDER BY id DESC LIMIT 1"
        )
        prev_row = await prev_cursor.fetchone()
        if prev_row:
            previous_hash = str(prev_row["event_hash"] or "")
        event_hash = _audit_event_hash(
            event_type=event_type,
            actor=actor,
            session_id=session_id,
            reason=reason,
            payload_json=payload_json,
            signature=signature,
            created_at=created_at,
            prev_hash=previous_hash,
        )
        await db.execute(
            """INSERT INTO memory_audit_log
               (event_type, actor, session_id, reason, payload, signature, prev_hash, event_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_type,
                actor,
                session_id,
                reason,
                payload_json,
                signature,
                previous_hash,
                event_hash,
                created_at,
            )
        )
        await db.commit()
        return event_hash
    finally:
        await db.close()


async def get_memory_audit_events(limit: int = 200, offset: int = 0):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM memory_audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, max(0, offset))
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def backfill_memory_audit_chain() -> dict:
    """Backfill prev_hash/event_hash for older audit rows."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, event_type, actor, session_id, reason, payload, signature, created_at, prev_hash, event_hash
               FROM memory_audit_log ORDER BY id ASC"""
        )
        rows = [dict(r) for r in await cursor.fetchall()]
        if not rows:
            return {"rows": 0, "updated": 0, "last_hash": ""}

        previous_hash = ""
        updated = 0
        for row in rows:
            expected_hash = _audit_event_hash(
                event_type=str(row.get("event_type") or ""),
                actor=str(row.get("actor") or ""),
                session_id=row.get("session_id"),
                reason=row.get("reason"),
                payload_json=str(row.get("payload") or "{}"),
                signature=row.get("signature"),
                created_at=str(row.get("created_at") or ""),
                prev_hash=previous_hash,
            )
            current_prev = str(row.get("prev_hash") or "")
            current_hash = str(row.get("event_hash") or "")
            if current_prev != previous_hash or current_hash != expected_hash:
                await db.execute(
                    "UPDATE memory_audit_log SET prev_hash = ?, event_hash = ? WHERE id = ?",
                    (previous_hash, expected_hash, row["id"]),
                )
                updated += 1
            previous_hash = expected_hash
        await db.commit()
        return {"rows": len(rows), "updated": updated, "last_hash": previous_hash}
    finally:
        await db.close()


async def verify_memory_audit_chain(limit: int = 5000) -> dict:
    """Verify integrity of append-only memory audit hash chain."""
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT id, event_type, actor, session_id, reason, payload, signature, created_at, prev_hash, event_hash
               FROM memory_audit_log ORDER BY id ASC LIMIT ?""",
            (max(1, min(limit, 200000)),),
        )
        rows = [dict(r) for r in await cursor.fetchall()]
        if not rows:
            return {"valid": True, "checked": 0, "broken": 0, "first_error_id": None, "last_hash": ""}

        previous_hash = ""
        broken = 0
        first_error_id: Optional[int] = None
        for row in rows:
            expected_hash = _audit_event_hash(
                event_type=str(row.get("event_type") or ""),
                actor=str(row.get("actor") or ""),
                session_id=row.get("session_id"),
                reason=row.get("reason"),
                payload_json=str(row.get("payload") or "{}"),
                signature=row.get("signature"),
                created_at=str(row.get("created_at") or ""),
                prev_hash=previous_hash,
            )
            current_prev = str(row.get("prev_hash") or "")
            current_hash = str(row.get("event_hash") or "")
            if current_prev != previous_hash or current_hash != expected_hash:
                broken += 1
                if first_error_id is None:
                    first_error_id = int(row.get("id") or 0)
            previous_hash = current_hash or expected_hash

        return {
            "valid": broken == 0,
            "checked": len(rows),
            "broken": broken,
            "first_error_id": first_error_id,
            "last_hash": previous_hash,
        }
    finally:
        await db.close()


async def get_memory_stats(session_id: Optional[str] = None):
    db = await get_db()
    try:
        if session_id:
            count_cursor = await db.execute(
                "SELECT COUNT(*) as c FROM memory_items WHERE session_id = ?",
                (session_id,)
            )
            avg_cursor = await db.execute(
                "SELECT COALESCE(AVG(importance), 0) as avg_importance FROM memory_items WHERE session_id = ?",
                (session_id,)
            )
            type_cursor = await db.execute(
                "SELECT memory_type, COUNT(*) as c FROM memory_items WHERE session_id = ? GROUP BY memory_type",
                (session_id,)
            )
        else:
            count_cursor = await db.execute("SELECT COUNT(*) as c FROM memory_items")
            avg_cursor = await db.execute("SELECT COALESCE(AVG(importance), 0) as avg_importance FROM memory_items")
            type_cursor = await db.execute("SELECT memory_type, COUNT(*) as c FROM memory_items GROUP BY memory_type")

        total = (await count_cursor.fetchone())["c"]
        avg_importance = (await avg_cursor.fetchone())["avg_importance"]
        by_type_rows = await type_cursor.fetchall()
        by_type = {row["memory_type"]: row["c"] for row in by_type_rows}
        now = _utcnow_iso()
        soon = (_utcnow() + timedelta(days=7)).isoformat()
        ttl_expired_cursor = await db.execute(
            "SELECT COUNT(*) AS c FROM memory_items WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (now,),
        )
        ttl_soon_cursor = await db.execute(
            "SELECT COUNT(*) AS c FROM memory_items WHERE expires_at IS NOT NULL AND expires_at > ? AND expires_at <= ?",
            (now, soon),
        )
        if session_id:
            source_quality_cursor = await db.execute(
                """SELECT source_type, COALESCE(AVG(confidence), 0) AS avg_confidence, COUNT(*) AS c
                   FROM memory_items WHERE session_id = ? GROUP BY source_type""",
                (session_id,),
            )
        else:
            source_quality_cursor = await db.execute(
                """SELECT source_type, COALESCE(AVG(confidence), 0) AS avg_confidence, COUNT(*) AS c
                   FROM memory_items GROUP BY source_type"""
            )
        prune_event_cursor = await db.execute(
            "SELECT COUNT(*) AS c FROM memory_audit_log WHERE event_type = 'memory_prune'"
        )
        source_quality_rows = await source_quality_cursor.fetchall()
        source_quality = {
            row["source_type"]: {
                "avg_confidence": round(float(row["avg_confidence"] or 0.0), 4),
                "count": int(row["c"] or 0),
            }
            for row in source_quality_rows
        }
        return {
            "total_items": total,
            "avg_importance": round(float(avg_importance or 0.0), 4),
            "by_type": by_type,
            "source_quality": source_quality,
            "ttl": {
                "expired_items": int((await ttl_expired_cursor.fetchone())["c"]),
                "expiring_within_7d": int((await ttl_soon_cursor.fetchone())["c"]),
            },
            "prune_events": int((await prune_event_cursor.fetchone())["c"]),
        }
    finally:
        await db.close()


async def list_memory_sessions(limit: int = 200):
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT session_id, MAX(created_at) AS last_seen, COUNT(*) AS memory_count
               FROM memory_items
               WHERE session_id IS NOT NULL
               GROUP BY session_id
               ORDER BY last_seen DESC
               LIMIT ?""",
            (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


# --- Auth / API keys ---


async def upsert_api_key(name: str, plaintext_key: str, role: str = "operator", scopes: Optional[list[str]] = None):
    key_id = str(uuid.uuid4())
    key_hash = hashlib.sha256((plaintext_key or "").encode("utf-8")).hexdigest()
    role_norm = (role or "operator").strip().lower()
    if role_norm not in {"viewer", "operator", "admin"}:
        role_norm = "operator"
    now = _utcnow_iso()

    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO api_keys (id, name, key_hash, role, scopes, created_at, revoked_at)
               VALUES (?, ?, ?, ?, ?, ?, NULL)
               ON CONFLICT(name) DO UPDATE SET
                 key_hash = excluded.key_hash,
                 role = excluded.role,
                 scopes = excluded.scopes,
                 created_at = excluded.created_at,
                 revoked_at = NULL""",
            (key_id, name, key_hash, role_norm, _json_dumps(scopes or []), now),
        )
        await db.commit()
        cursor = await db.execute("SELECT id FROM api_keys WHERE name = ?", (name,))
        row = await cursor.fetchone()
        return str(row["id"]) if row else key_id
    finally:
        await db.close()


async def get_api_key_by_hash(key_hash: str):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL",
            (key_hash,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        result = dict(row)
        try:
            parsed = json.loads(result.get("scopes") or "[]")
            result["scopes"] = parsed if isinstance(parsed, list) else []
        except Exception:
            result["scopes"] = []
        return result
    finally:
        await db.close()


async def list_api_keys(limit: int = 200):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id, name, role, scopes, created_at, revoked_at FROM api_keys ORDER BY created_at DESC LIMIT ?",
            (max(1, min(limit, 1000)),),
        )
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                parsed = json.loads(item.get("scopes") or "[]")
                item["scopes"] = parsed if isinstance(parsed, list) else []
            except Exception:
                item["scopes"] = []
            result.append(item)
        return result
    finally:
        await db.close()


async def revoke_api_key(name_or_id: str) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "UPDATE api_keys SET revoked_at = ? WHERE (name = ? OR id = ?) AND revoked_at IS NULL",
            (_utcnow_iso(), name_or_id, name_or_id),
        )
        await db.commit()
        return int(cursor.rowcount or 0)
    finally:
        await db.close()


# --- Swarm orchestration ---


async def create_swarm_run(
    *,
    run_id: str,
    target: str,
    objective: str,
    methodology: str = "owasp",
    scan_type: str = "quick",
    config: Optional[dict] = None,
    status: str = "queued",
) -> str:
    now = _utcnow_iso()
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO swarm_runs
               (run_id, target, objective, methodology, scan_type, config, status, error, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)""",
            (
                run_id,
                target,
                objective,
                methodology,
                scan_type,
                _json_dumps(config or {}),
                status,
                now,
                now,
            ),
        )
        await db.commit()
        return run_id
    finally:
        await db.close()


async def update_swarm_run(run_id: str, **kwargs):
    if not kwargs:
        return
    db = await get_db()
    try:
        sets = []
        values = []
        for key, value in kwargs.items():
            sets.append(f"{key} = ?")
            values.append(value)
        sets.append("updated_at = ?")
        values.append(_utcnow_iso())
        values.append(run_id)
        await db.execute(f"UPDATE swarm_runs SET {', '.join(sets)} WHERE run_id = ?", values)
        await db.commit()
    finally:
        await db.close()


async def get_swarm_run(run_id: str):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM swarm_runs WHERE run_id = ?", (run_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        item = dict(row)
        try:
            item["config"] = json.loads(item.get("config") or "{}")
        except Exception:
            item["config"] = {}
        return item
    finally:
        await db.close()


async def list_swarm_runs(limit: int = 50, offset: int = 0, status: Optional[str] = None):
    db = await get_db()
    try:
        params: list[Any] = []
        where = ""
        if status:
            where = "WHERE status = ?"
            params.append(status)
        params.extend([max(1, min(limit, 1000)), max(0, offset)])
        cursor = await db.execute(
            f"SELECT * FROM swarm_runs {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        )
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["config"] = json.loads(item.get("config") or "{}")
            except Exception:
                item["config"] = {}
            result.append(item)
        return result
    finally:
        await db.close()


async def upsert_swarm_task(
    *,
    run_id: str,
    task_id: str,
    agent: str,
    task: str,
    dependencies: Optional[list[str]] = None,
    priority: int = 0,
    max_attempts: int = 1,
    timeout_sec: int = 90,
):
    now = _utcnow_iso()
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO swarm_tasks
               (run_id, task_id, agent, task, dependencies, priority, status, attempt, max_attempts, timeout_sec, result, error, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 'queued', 0, ?, ?, NULL, NULL, ?)
               ON CONFLICT(run_id, task_id) DO UPDATE SET
                 agent = excluded.agent,
                 task = excluded.task,
                 dependencies = excluded.dependencies,
                 priority = excluded.priority,
                 max_attempts = excluded.max_attempts,
                 timeout_sec = excluded.timeout_sec""",
            (
                run_id,
                task_id,
                agent,
                task,
                _json_dumps(dependencies or []),
                int(priority),
                int(max_attempts),
                int(timeout_sec),
                now,
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def list_swarm_tasks(run_id: str):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM swarm_tasks WHERE run_id = ? ORDER BY priority DESC, id ASC",
            (run_id,),
        )
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["dependencies"] = json.loads(item.get("dependencies") or "[]")
            except Exception:
                item["dependencies"] = []
            try:
                item["result"] = json.loads(item.get("result") or "null")
            except Exception:
                item["result"] = item.get("result")
            result.append(item)
        return result
    finally:
        await db.close()


async def get_swarm_task(run_id: str, task_id: str):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM swarm_tasks WHERE run_id = ? AND task_id = ?",
            (run_id, task_id),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        item = dict(row)
        try:
            item["dependencies"] = json.loads(item.get("dependencies") or "[]")
        except Exception:
            item["dependencies"] = []
        try:
            item["result"] = json.loads(item.get("result") or "null")
        except Exception:
            item["result"] = item.get("result")
        return item
    finally:
        await db.close()


async def update_swarm_task(run_id: str, task_id: str, **kwargs):
    if not kwargs:
        return
    db = await get_db()
    try:
        sets = []
        values = []
        for key, value in kwargs.items():
            if key == "result":
                value = _json_dumps(value)
            sets.append(f"{key} = ?")
            values.append(value)
        values.extend([run_id, task_id])
        await db.execute(
            f"UPDATE swarm_tasks SET {', '.join(sets)} WHERE run_id = ? AND task_id = ?",
            values,
        )
        await db.commit()
    finally:
        await db.close()


async def add_swarm_event(run_id: str, event_type: str, payload: Optional[dict] = None):
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO swarm_events (run_id, event_type, payload, created_at)
               VALUES (?, ?, ?, ?)""",
            (run_id, event_type, _json_dumps(payload or {}), _utcnow_iso()),
        )
        await db.commit()
    finally:
        await db.close()


async def list_swarm_events(run_id: str, limit: int = 500):
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM swarm_events
               WHERE run_id = ?
               ORDER BY id DESC
               LIMIT ?""",
            (run_id, max(1, min(limit, 5000))),
        )
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["payload"] = json.loads(item.get("payload") or "{}")
            except Exception:
                item["payload"] = {}
            result.append(item)
        return list(reversed(result))
    finally:
        await db.close()


async def count_swarm_events_since(
    *,
    event_type: str,
    since_iso: str,
    run_id: Optional[str] = None,
) -> int:
    db = await get_db()
    try:
        if run_id:
            cursor = await db.execute(
                """SELECT COUNT(*) AS c
                   FROM swarm_events
                   WHERE run_id = ? AND event_type = ? AND created_at >= ?""",
                (run_id, event_type, since_iso),
            )
        else:
            cursor = await db.execute(
                """SELECT COUNT(*) AS c
                   FROM swarm_events
                   WHERE event_type = ? AND created_at >= ?""",
                (event_type, since_iso),
            )
        row = await cursor.fetchone()
        return int(row["c"] if row else 0)
    finally:
        await db.close()


# --- Crawler policy ---


async def upsert_crawler_policy(
    domain: str,
    allow: bool = True,
    max_depth: Optional[int] = None,
    daily_cap: Optional[int] = None,
    trust_floor: Optional[float] = None,
):
    policy_id = str(uuid.uuid4())
    now = _utcnow_iso()
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO crawler_policy (id, domain, allow, max_depth, daily_cap, trust_floor, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(domain) DO UPDATE SET
                 allow = excluded.allow,
                 max_depth = excluded.max_depth,
                 daily_cap = excluded.daily_cap,
                 trust_floor = excluded.trust_floor,
                 updated_at = excluded.updated_at""",
            (
                policy_id,
                domain.strip().lower(),
                1 if allow else 0,
                max_depth,
                daily_cap,
                trust_floor,
                now,
                now,
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def get_crawler_policy_for_domain(domain: str):
    domain = (domain or "").strip().lower()
    if not domain:
        return None
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM crawler_policy
               WHERE domain = ? OR ? LIKE ('%.' || domain) OR domain = '*'
               ORDER BY
                 CASE WHEN domain = ? THEN 0 WHEN domain = '*' THEN 2 ELSE 1 END,
                 LENGTH(domain) DESC
               LIMIT 1""",
            (domain, domain, domain),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def list_crawler_policies(limit: int = 500):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM crawler_policy ORDER BY updated_at DESC LIMIT ?",
            (max(1, min(limit, 5000)),),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


# --- Persistent learning sources ---


def _normalize_learning_source_url(seed_url: str) -> tuple[str, str]:
    raw = (seed_url or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        parsed = urlparse(f"https://{raw}")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return "", ""
    domain = (parsed.hostname or "").strip().lower()
    normalized = parsed._replace(fragment="").geturl()
    return normalized, domain


def _learning_profile_defaults(profile: str) -> dict:
    p = (profile or "").strip().lower()
    if p == "conservative":
        return {
            "profile": "conservative",
            "max_depth": 3,
            "max_pages_per_domain": 120,
            "max_pages_per_day": 600,
            "allow_subdomains": 1,
            "recrawl_interval_min": 720,
        }
    if p == "balanced":
        return {
            "profile": "balanced",
            "max_depth": 4,
            "max_pages_per_domain": 220,
            "max_pages_per_day": 1200,
            "allow_subdomains": 1,
            "recrawl_interval_min": 480,
        }
    return {
        "profile": "aggressive_deep",
        "max_depth": 6,
        "max_pages_per_domain": 300,
        "max_pages_per_day": 2500,
        "allow_subdomains": 1,
        "recrawl_interval_min": 360,
    }


def _coerce_int(value: Any, default: int, lo: int, hi: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    return max(lo, min(hi, parsed))


def _decode_learning_source_row(row: dict | None) -> Optional[dict]:
    if not row:
        return None
    item = dict(row)
    for key in ("enabled", "allow_subdomains"):
        item[key] = bool(int(item.get(key) or 0))
    item["consecutive_failures"] = int(item.get("consecutive_failures") or 0)
    for key in ("max_depth", "max_pages_per_domain", "max_pages_per_day", "recrawl_interval_min"):
        item[key] = int(item.get(key) or 0)
    try:
        meta = json.loads(item.get("metadata") or "{}")
        item["metadata"] = meta if isinstance(meta, dict) else {}
    except Exception:
        item["metadata"] = {}
    return item


def _decode_frontier_row(row: dict | None) -> Optional[dict]:
    if not row:
        return None
    item = dict(row)
    item["depth"] = int(item.get("depth") or 0)
    item["priority"] = int(item.get("priority") or 0)
    return item


async def add_learning_source_event(source_id: str, event_type: str, payload: Optional[dict] = None):
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO learning_source_events (source_id, event_type, payload, created_at)
               VALUES (?, ?, ?, ?)""",
            (source_id, event_type, _json_dumps(payload or {}), _utcnow_iso()),
        )
        await db.commit()
    finally:
        await db.close()


async def list_learning_source_events(source_id: str, limit: int = 200):
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM learning_source_events
               WHERE source_id = ?
               ORDER BY id DESC
               LIMIT ?""",
            (source_id, max(1, min(limit, 2000))),
        )
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                payload = json.loads(item.get("payload") or "{}")
                item["payload"] = payload if isinstance(payload, dict) else {}
            except Exception:
                item["payload"] = {}
            result.append(item)
        return list(reversed(result))
    finally:
        await db.close()


async def upsert_learning_source(
    *,
    seed_url: str,
    profile: str,
    enabled: bool = True,
    max_depth: Optional[int] = None,
    max_pages_per_domain: Optional[int] = None,
    max_pages_per_day: Optional[int] = None,
    allow_subdomains: Optional[bool] = None,
    recrawl_interval_min: Optional[int] = None,
    metadata: Optional[dict] = None,
) -> dict:
    normalized, domain = _normalize_learning_source_url(seed_url)
    if not normalized or not domain:
        raise ValueError("invalid_seed_url")
    defaults = _learning_profile_defaults(profile)
    now = _utcnow_iso()
    row_id = str(uuid.uuid4())
    payload = {
        "profile": defaults["profile"],
        "max_depth": _coerce_int(max_depth, defaults["max_depth"], 0, 8),
        "max_pages_per_domain": _coerce_int(max_pages_per_domain, defaults["max_pages_per_domain"], 1, 2000),
        "max_pages_per_day": _coerce_int(max_pages_per_day, defaults["max_pages_per_day"], 10, 10000),
        "allow_subdomains": 1 if (defaults["allow_subdomains"] if allow_subdomains is None else bool(allow_subdomains)) else 0,
        "recrawl_interval_min": _coerce_int(recrawl_interval_min, defaults["recrawl_interval_min"], 10, 10080),
        "metadata": metadata if isinstance(metadata, dict) else {},
    }
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO learning_sources
               (id, seed_url, domain, enabled, profile, max_depth, max_pages_per_domain, max_pages_per_day,
                allow_subdomains, recrawl_interval_min, last_run_at, next_run_at, consecutive_failures, metadata,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, 0, ?, ?, ?)
               ON CONFLICT(seed_url) DO UPDATE SET
                 domain = excluded.domain,
                 enabled = excluded.enabled,
                 profile = excluded.profile,
                 max_depth = excluded.max_depth,
                 max_pages_per_domain = excluded.max_pages_per_domain,
                 max_pages_per_day = excluded.max_pages_per_day,
                 allow_subdomains = excluded.allow_subdomains,
                 recrawl_interval_min = excluded.recrawl_interval_min,
                 metadata = excluded.metadata,
                 updated_at = excluded.updated_at""",
            (
                row_id,
                normalized,
                domain,
                1 if enabled else 0,
                payload["profile"],
                payload["max_depth"],
                payload["max_pages_per_domain"],
                payload["max_pages_per_day"],
                payload["allow_subdomains"],
                payload["recrawl_interval_min"],
                now,
                _json_dumps(payload["metadata"]),
                now,
                now,
            ),
        )
        await db.commit()
    finally:
        await db.close()
    source = await get_learning_source_by_seed(normalized)
    return source or {}


async def get_learning_source(source_id: str):
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM learning_sources WHERE id = ?", (source_id,))
        row = await cursor.fetchone()
        return _decode_learning_source_row(dict(row)) if row else None
    finally:
        await db.close()


async def get_learning_source_by_seed(seed_url: str):
    normalized, _domain = _normalize_learning_source_url(seed_url)
    if not normalized:
        return None
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM learning_sources WHERE seed_url = ?", (normalized,))
        row = await cursor.fetchone()
        return _decode_learning_source_row(dict(row)) if row else None
    finally:
        await db.close()


async def list_learning_sources(enabled_only: bool = False, limit: int = 200, offset: int = 0):
    db = await get_db()
    try:
        if enabled_only:
            cursor = await db.execute(
                """SELECT * FROM learning_sources
                   WHERE enabled = 1
                   ORDER BY updated_at DESC
                   LIMIT ? OFFSET ?""",
                (max(1, min(limit, 2000)), max(0, offset)),
            )
        else:
            cursor = await db.execute(
                """SELECT * FROM learning_sources
                   ORDER BY updated_at DESC
                   LIMIT ? OFFSET ?""",
                (max(1, min(limit, 2000)), max(0, offset)),
            )
        rows = await cursor.fetchall()
        return [_decode_learning_source_row(dict(r)) for r in rows]
    finally:
        await db.close()


async def count_learning_sources(enabled_only: bool = False) -> int:
    db = await get_db()
    try:
        if enabled_only:
            cursor = await db.execute("SELECT COUNT(*) AS c FROM learning_sources WHERE enabled = 1")
        else:
            cursor = await db.execute("SELECT COUNT(*) AS c FROM learning_sources")
        row = await cursor.fetchone()
        return int(row["c"] if row else 0)
    finally:
        await db.close()


async def update_learning_source(source_id: str, **kwargs):
    allowed = {
        "enabled",
        "profile",
        "max_depth",
        "max_pages_per_domain",
        "max_pages_per_day",
        "allow_subdomains",
        "recrawl_interval_min",
        "last_run_at",
        "next_run_at",
        "consecutive_failures",
        "metadata",
    }
    sets: list[str] = []
    values: list[Any] = []
    for key, value in kwargs.items():
        if key not in allowed:
            continue
        if key in {"enabled", "allow_subdomains"}:
            value = 1 if bool(value) else 0
        if key == "metadata":
            value = _json_dumps(value if isinstance(value, dict) else {})
        sets.append(f"{key} = ?")
        values.append(value)
    if not sets:
        return 0
    sets.append("updated_at = ?")
    values.append(_utcnow_iso())
    values.append(source_id)
    db = await get_db()
    try:
        cursor = await db.execute(
            f"UPDATE learning_sources SET {', '.join(sets)} WHERE id = ?",
            tuple(values),
        )
        await db.commit()
        return int(cursor.rowcount or 0)
    finally:
        await db.close()


async def list_due_learning_sources(limit: int = 20):
    now = _utcnow_iso()
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM learning_sources
               WHERE enabled = 1
                 AND (next_run_at IS NULL OR next_run_at <= ?)
               ORDER BY COALESCE(next_run_at, created_at) ASC
               LIMIT ?""",
            (now, max(1, min(limit, 500))),
        )
        rows = await cursor.fetchall()
        return [_decode_learning_source_row(dict(r)) for r in rows]
    finally:
        await db.close()


async def upsert_learning_frontier_url(
    *,
    source_id: str,
    url: str,
    domain: str,
    depth: int,
    priority: int = 0,
    discovered_from: Optional[str] = None,
    status: str = "queued",
) -> tuple[str, bool]:
    db = await get_db()
    now = _utcnow_iso()
    frontier_id = str(uuid.uuid4())
    try:
        await db.execute(
            """INSERT INTO learning_frontier
               (id, source_id, url, domain, depth, priority, status, discovered_from,
                last_error, first_seen_at, last_seen_at, next_retry_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, NULL)
               ON CONFLICT(source_id, url) DO UPDATE SET
                 domain = excluded.domain,
                 depth = MIN(learning_frontier.depth, excluded.depth),
                 priority = MAX(learning_frontier.priority, excluded.priority),
                 last_seen_at = excluded.last_seen_at,
                 discovered_from = COALESCE(learning_frontier.discovered_from, excluded.discovered_from),
                 status = CASE
                     WHEN learning_frontier.status IN ('error','skipped','done') THEN 'queued'
                     ELSE learning_frontier.status
                 END,
                 next_retry_at = NULL""",
            (
                frontier_id,
                source_id,
                url,
                domain,
                int(depth),
                int(priority),
                status,
                discovered_from,
                now,
                now,
            ),
        )
        await db.commit()
        cursor = await db.execute(
            "SELECT id, first_seen_at = last_seen_at AS is_new FROM learning_frontier WHERE source_id = ? AND url = ?",
            (source_id, url),
        )
        row = await cursor.fetchone()
        if not row:
            return frontier_id, False
        return str(row["id"]), bool(int(row["is_new"] or 0))
    finally:
        await db.close()


async def claim_learning_frontier(source_id: str, limit: int = 20):
    claimed_rows: list[dict] = []

    async def _run():
        nonlocal claimed_rows
        db = await get_db()
        try:
            await db.execute("BEGIN IMMEDIATE")
            now = _utcnow_iso()
            cursor = await db.execute(
                """SELECT id FROM learning_frontier
                   WHERE source_id = ?
                     AND status = 'queued'
                     AND (next_retry_at IS NULL OR next_retry_at <= ?)
                   ORDER BY priority DESC, depth ASC, last_seen_at ASC
                   LIMIT ?""",
                (source_id, now, max(1, min(limit, 500))),
            )
            ids = [str(r["id"]) for r in await cursor.fetchall()]
            if ids:
                await db.execute(
                    f"""UPDATE learning_frontier
                        SET status = 'running', last_seen_at = ?
                        WHERE id IN ({','.join('?' for _ in ids)})""",
                    (now, *ids),
                )
            await db.commit()
            if not ids:
                claimed_rows = []
                return
            cursor = await db.execute(
                f"SELECT * FROM learning_frontier WHERE id IN ({','.join('?' for _ in ids)})",
                tuple(ids),
            )
            rows = await cursor.fetchall()
            claimed_rows = [_decode_frontier_row(dict(r)) for r in rows]
        except Exception:
            await db.rollback()
            raise
        finally:
            await db.close()

    await _with_retry(_run)
    return claimed_rows


async def update_learning_frontier_status(
    frontier_id: str,
    *,
    status: str,
    last_error: Optional[str] = None,
    next_retry_at: Optional[str] = None,
):
    db = await get_db()
    try:
        await db.execute(
            """UPDATE learning_frontier
               SET status = ?, last_error = ?, next_retry_at = ?, last_seen_at = ?
               WHERE id = ?""",
            (status, last_error, next_retry_at, _utcnow_iso(), frontier_id),
        )
        await db.commit()
    finally:
        await db.close()


async def list_learning_frontier(source_id: str, status: Optional[str] = None, limit: int = 200):
    db = await get_db()
    try:
        if status:
            cursor = await db.execute(
                """SELECT * FROM learning_frontier
                   WHERE source_id = ? AND status = ?
                   ORDER BY priority DESC, depth ASC, last_seen_at ASC
                   LIMIT ?""",
                (source_id, status, max(1, min(limit, 2000))),
            )
        else:
            cursor = await db.execute(
                """SELECT * FROM learning_frontier
                   WHERE source_id = ?
                   ORDER BY last_seen_at DESC
                   LIMIT ?""",
                (source_id, max(1, min(limit, 2000))),
            )
        rows = await cursor.fetchall()
        return [_decode_frontier_row(dict(r)) for r in rows]
    finally:
        await db.close()


async def count_learning_frontier(source_id: Optional[str] = None, status: Optional[str] = None) -> int:
    db = await get_db()
    try:
        clauses = []
        params: list[Any] = []
        if source_id:
            clauses.append("source_id = ?")
            params.append(source_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        cursor = await db.execute(f"SELECT COUNT(*) AS c FROM learning_frontier {where}", tuple(params))
        row = await cursor.fetchone()
        return int(row["c"] if row else 0)
    finally:
        await db.close()


async def upsert_learning_checkpoint(source_id: str, checkpoint: dict):
    now = _utcnow_iso()
    row_id = str(uuid.uuid4())
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO learning_checkpoints (id, source_id, checkpoint_json, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(source_id) DO UPDATE SET
                 checkpoint_json = excluded.checkpoint_json,
                 updated_at = excluded.updated_at""",
            (row_id, source_id, _json_dumps(checkpoint if isinstance(checkpoint, dict) else {}), now, now),
        )
        await db.commit()
    finally:
        await db.close()


async def get_learning_checkpoint(source_id: str):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM learning_checkpoints WHERE source_id = ?",
            (source_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        item = dict(row)
        try:
            decoded = json.loads(item.get("checkpoint_json") or "{}")
            item["checkpoint"] = decoded if isinstance(decoded, dict) else {}
        except Exception:
            item["checkpoint"] = {}
        return item
    finally:
        await db.close()


async def count_running_jobs_by_type(job_type: str) -> int:
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT COUNT(*) AS c FROM job_queue WHERE type = ? AND status = 'running'",
            (job_type,),
        )
        row = await cursor.fetchone()
        return int(row["c"] if row else 0)
    finally:
        await db.close()


# --- Worker heartbeat ---


async def upsert_worker_heartbeat(worker_id: str, role: str, meta: Optional[dict] = None):
    now = _utcnow_iso()
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO worker_heartbeats (worker_id, role, updated_at, meta)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(worker_id) DO UPDATE SET
                 role = excluded.role,
                 updated_at = excluded.updated_at,
                 meta = excluded.meta""",
            (
                str(worker_id or "").strip(),
                str(role or "worker").strip().lower(),
                now,
                _json_dumps(meta if isinstance(meta, dict) else {}),
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def get_worker_heartbeat(role: str = "worker") -> Optional[dict]:
    r = str(role or "worker").strip().lower()
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM worker_heartbeats
               WHERE role = ?
               ORDER BY updated_at DESC
               LIMIT 1""",
            (r,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        item = dict(row)
        try:
            decoded = json.loads(item.get("meta") or "{}")
            item["meta"] = decoded if isinstance(decoded, dict) else {}
        except Exception:
            item["meta"] = {}
        return item
    finally:
        await db.close()


async def list_worker_heartbeats(limit: int = 50, role: Optional[str] = None) -> list[dict]:
    db = await get_db()
    try:
        params: list[Any] = []
        where = ""
        if role:
            where = "WHERE role = ?"
            params.append(str(role).strip().lower())
        params.append(max(1, min(limit, 500)))
        cursor = await db.execute(
            f"SELECT * FROM worker_heartbeats {where} ORDER BY updated_at DESC LIMIT ?",
            tuple(params),
        )
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                decoded = json.loads(item.get("meta") or "{}")
                item["meta"] = decoded if isinstance(decoded, dict) else {}
            except Exception:
                item["meta"] = {}
            result.append(item)
        return result
    finally:
        await db.close()


# --- Command policy ---


async def upsert_command_policy(
    tool_name: str,
    allowed_args: Optional[list[str]] = None,
    blocked_args: Optional[list[str]] = None,
    hitl_required: bool = False,
):
    policy_id = str(uuid.uuid4())
    now = _utcnow_iso()
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO command_policy (id, tool_name, allowed_args, blocked_args, hitl_required, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(tool_name) DO UPDATE SET
                 allowed_args = excluded.allowed_args,
                 blocked_args = excluded.blocked_args,
                 hitl_required = excluded.hitl_required,
                 updated_at = excluded.updated_at""",
            (
                policy_id,
                (tool_name or "").strip().lower(),
                _json_dumps(allowed_args or []),
                _json_dumps(blocked_args or []),
                1 if hitl_required else 0,
                now,
                now,
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def get_command_policy(tool_name: str):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM command_policy WHERE tool_name = ?",
            ((tool_name or "").strip().lower(),),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        item = dict(row)
        for key in ("allowed_args", "blocked_args"):
            try:
                parsed = json.loads(item.get(key) or "[]")
                item[key] = parsed if isinstance(parsed, list) else []
            except Exception:
                item[key] = []
        item["hitl_required"] = bool(int(item.get("hitl_required") or 0))
        return item
    finally:
        await db.close()


async def list_command_policies(limit: int = 500):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM command_policy ORDER BY updated_at DESC LIMIT ?",
            (max(1, min(limit, 5000)),),
        )
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            item = dict(row)
            for key in ("allowed_args", "blocked_args"):
                try:
                    parsed = json.loads(item.get(key) or "[]")
                    item[key] = parsed if isinstance(parsed, list) else []
                except Exception:
                    item[key] = []
            item["hitl_required"] = bool(int(item.get("hitl_required") or 0))
            result.append(item)
        return result
    finally:
        await db.close()


# --- Target Allowlist ---


def _normalize_target_allowlist_pattern(rule_type: str, pattern: str) -> str:
    raw = (pattern or "").strip()
    if not raw:
        return ""
    rtype = (rule_type or "").strip().lower()
    if rtype == "domain":
        parsed = urlparse(raw if "://" in raw else f"http://{raw}")
        host = (parsed.hostname or "").strip().lower()
        if not host:
            host = raw.split("/", 1)[0].strip().lower()
        host = host.split(":", 1)[0].strip().lstrip(".").rstrip(".")
        return host
    return raw.strip().lower()


async def add_target_rule(rule_type: str, pattern: str, created_by: str = "api", enabled: bool = True):
    rule_type_norm = (rule_type or "").strip().lower()
    pattern_norm = _normalize_target_allowlist_pattern(rule_type_norm, pattern)
    if not pattern_norm:
        pattern_norm = (pattern or "").strip()

    db = await get_db()
    try:
        # Idempotency: avoid inserting duplicates when the same type+pattern is added repeatedly.
        cursor = await db.execute(
            "SELECT id, pattern FROM target_allowlist WHERE type = ? ORDER BY created_at DESC LIMIT 5000",
            (rule_type_norm,),
        )
        for row in await cursor.fetchall():
            existing_norm = _normalize_target_allowlist_pattern(rule_type_norm, str(row["pattern"] or ""))
            if existing_norm and existing_norm == pattern_norm:
                return str(row["id"])

        rule_id = str(uuid.uuid4())
        await db.execute(
            """INSERT INTO target_allowlist (id, type, pattern, enabled, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (rule_id, rule_type_norm, pattern_norm, 1 if enabled else 0, created_by, _utcnow_iso()),
        )
        await db.commit()
        return rule_id
    finally:
        await db.close()


async def list_target_rules(enabled_only: bool = False):
    db = await get_db()
    try:
        if enabled_only:
            cursor = await db.execute(
                "SELECT * FROM target_allowlist WHERE enabled = 1 ORDER BY created_at DESC"
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM target_allowlist ORDER BY created_at DESC"
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def delete_target_rule(rule_id: str):
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM target_allowlist WHERE id = ?", (rule_id,))
        await db.commit()
        return cursor.rowcount if cursor else 0
    finally:
        await db.close()


# --- Job Queue ---


async def enqueue_job(
    job_type: str,
    payload: dict,
    *,
    max_attempts: int = 3,
    next_run_at: Optional[str] = None,
    status: str = "queued",
) -> str:
    job_id = str(uuid.uuid4())
    now = _utcnow_iso()

    async def _run():
        db = await get_db()
        try:
            await db.execute(
                """INSERT INTO job_queue
                   (id, type, payload, status, attempt, max_attempts, next_run_at, error, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 0, ?, ?, NULL, ?, ?)""",
                (
                    job_id,
                    job_type,
                    _json_dumps(payload or {}),
                    status,
                    int(max_attempts),
                    next_run_at or now,
                    now,
                    now,
                ),
            )
            await db.commit()
        finally:
            await db.close()

    await _with_retry(_run)
    return job_id


async def count_pending_jobs(job_type: Optional[str] = None):
    db = await get_db()
    try:
        if job_type:
            cursor = await db.execute(
                "SELECT COUNT(*) AS c FROM job_queue WHERE type = ? AND status IN ('queued', 'running')",
                (job_type,),
            )
        else:
            cursor = await db.execute(
                "SELECT COUNT(*) AS c FROM job_queue WHERE status IN ('queued', 'running')"
            )
        row = await cursor.fetchone()
        return int(row["c"] if row else 0)
    finally:
        await db.close()


async def list_jobs(limit: int = 200, job_type: Optional[str] = None, status: Optional[str] = None):
    db = await get_db()
    try:
        clauses = []
        params = []
        if job_type:
            clauses.append("type = ?")
            params.append(job_type)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        cursor = await db.execute(
            f"SELECT * FROM job_queue {where} ORDER BY created_at DESC LIMIT ?",
            (*params, limit),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def list_scan_jobs(scan_id: str, limit: int = 50):
    db = await get_db()
    try:
        cursor = await db.execute(
            """SELECT * FROM job_queue
               WHERE type = 'scan' AND json_extract(payload, '$.scan_id') = ?
               ORDER BY created_at DESC
               LIMIT ?""",
            (scan_id, limit),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def claim_jobs(job_type: str, limit: int = 1, worker_id: Optional[str] = None, lease_seconds: int = JOB_LEASE_SECONDS):
    """Atomically claim due queued jobs for execution."""
    claimed_rows: list[dict] = []

    async def _run():
        nonlocal claimed_rows
        db = await get_db()
        try:
            await db.execute("BEGIN IMMEDIATE")
            now_dt = _utcnow()
            now = now_dt.isoformat()
            lease_until = (now_dt + timedelta(seconds=max(30, int(lease_seconds)))).isoformat()
            cursor = await db.execute(
                """SELECT id FROM job_queue
                   WHERE type = ? AND status = 'queued' AND next_run_at <= ?
                   ORDER BY next_run_at ASC, created_at ASC
                   LIMIT ?""",
                (job_type, now, limit),
            )
            ids = [row["id"] for row in await cursor.fetchall()]
            if ids:
                placeholders = ",".join("?" for _ in ids)
                await db.execute(
                    f"""UPDATE job_queue
                        SET status = 'running',
                            attempt = attempt + 1,
                            started_at = ?,
                            updated_at = ?,
                            heartbeat_at = ?,
                            lease_until = ?,
                            worker_id = ?,
                            error = NULL
                        WHERE id IN ({placeholders})""",
                    (now, now, now, lease_until, worker_id, *ids),
                )
            await db.commit()
            if not ids:
                claimed_rows = []
                return
            detail_cursor = await db.execute(
                f"SELECT * FROM job_queue WHERE id IN ({','.join('?' for _ in ids)})",
                tuple(ids),
            )
            rows = await detail_cursor.fetchall()
            claimed_rows = [dict(r) for r in rows]
        except Exception:
            await db.rollback()
            raise
        finally:
            await db.close()

    await _with_retry(_run)
    return claimed_rows


async def heartbeat_job(job_id: str, worker_id: Optional[str] = None, lease_seconds: int = JOB_LEASE_SECONDS):
    async def _run():
        db = await get_db()
        try:
            now_dt = _utcnow()
            now = now_dt.isoformat()
            lease_until = (now_dt + timedelta(seconds=max(30, int(lease_seconds)))).isoformat()
            if worker_id:
                await db.execute(
                    """UPDATE job_queue
                       SET heartbeat_at = ?, lease_until = ?, updated_at = ?
                       WHERE id = ? AND status = 'running' AND (worker_id IS NULL OR worker_id = ?)""",
                    (now, lease_until, now, job_id, worker_id),
                )
            else:
                await db.execute(
                    """UPDATE job_queue
                       SET heartbeat_at = ?, lease_until = ?, updated_at = ?
                       WHERE id = ? AND status = 'running'""",
                    (now, lease_until, now, job_id),
                )
            await db.commit()
        finally:
            await db.close()

    await _with_retry(_run)


async def reclaim_stale_running_jobs() -> int:
    reclaimed = 0

    async def _run():
        nonlocal reclaimed
        db = await get_db()
        try:
            now = _utcnow_iso()
            cursor = await db.execute(
                """UPDATE job_queue
                   SET status = 'queued',
                       updated_at = ?,
                       error = CASE
                           WHEN error IS NULL OR error = '' THEN 'recovered from stale lease'
                           ELSE error
                       END,
                       worker_id = NULL,
                       lease_until = NULL,
                       heartbeat_at = NULL
                   WHERE status = 'running'
                     AND lease_until IS NOT NULL
                     AND lease_until <= ?""",
                (now, now),
            )
            await db.commit()
            reclaimed = int(cursor.rowcount or 0)
        finally:
            await db.close()

    await _with_retry(_run)
    return reclaimed


async def complete_job(job_id: str):
    async def _run():
        db = await get_db()
        try:
            now = _utcnow_iso()
            await db.execute(
                """UPDATE job_queue
                   SET status = 'completed',
                       finished_at = ?,
                       updated_at = ?,
                       worker_id = NULL,
                       lease_until = NULL
                   WHERE id = ?""",
                (now, now, job_id),
            )
            await db.commit()
        finally:
            await db.close()

    await _with_retry(_run)


async def fail_job(job_id: str, error: str, *, retry_delay_sec: int = 0):
    async def _run():
        db = await get_db()
        try:
            now = _utcnow()
            next_run = (now + timedelta(seconds=max(0, retry_delay_sec))).isoformat()
            row_cursor = await db.execute(
                "SELECT attempt, max_attempts FROM job_queue WHERE id = ?",
                (job_id,),
            )
            row = await row_cursor.fetchone()
            if not row:
                return
            attempt = int(row["attempt"] or 0)
            max_attempts = int(row["max_attempts"] or 1)
            status = "failed" if attempt >= max_attempts else "queued"
            await db.execute(
                """UPDATE job_queue
                   SET status = ?,
                       error = ?,
                       next_run_at = ?,
                       updated_at = ?,
                       worker_id = NULL,
                       lease_until = NULL,
                       heartbeat_at = NULL,
                       finished_at = CASE WHEN ?='failed' THEN ? ELSE finished_at END
                   WHERE id = ?""",
                (status, (error or "")[:1000], next_run, now.isoformat(), status, now.isoformat(), job_id),
            )
            await db.commit()
        finally:
            await db.close()

    await _with_retry(_run)


async def cancel_jobs_for_scan(scan_id: str):
    async def _run():
        db = await get_db()
        try:
            now = _utcnow_iso()
            await db.execute(
                """UPDATE job_queue
                   SET status = 'cancelled',
                       updated_at = ?,
                       finished_at = ?,
                       worker_id = NULL,
                       lease_until = NULL,
                       heartbeat_at = NULL
                   WHERE type = 'scan'
                     AND status IN ('queued', 'running')
                     AND json_extract(payload, '$.scan_id') = ?""",
                (now, now, scan_id),
            )
            await db.commit()
        finally:
            await db.close()

    await _with_retry(_run)


async def cancel_swarm_jobs_for_run(run_id: str):
    async def _run():
        db = await get_db()
        try:
            now = _utcnow_iso()
            await db.execute(
                """UPDATE job_queue
                   SET status = 'cancelled',
                       updated_at = ?,
                       finished_at = ?,
                       worker_id = NULL,
                       lease_until = NULL,
                       heartbeat_at = NULL
                   WHERE type = 'swarm'
                     AND status IN ('queued', 'running')
                     AND json_extract(payload, '$.run_id') = ?""",
                (now, now, run_id),
            )
            await db.commit()
        finally:
            await db.close()

    await _with_retry(_run)


async def cancel_all_scan_jobs():
    async def _run():
        db = await get_db()
        try:
            now = _utcnow_iso()
            await db.execute(
                """UPDATE job_queue
                   SET status = 'cancelled',
                       updated_at = ?,
                       finished_at = ?,
                       worker_id = NULL,
                       lease_until = NULL,
                       heartbeat_at = NULL
                   WHERE type = 'scan' AND status IN ('queued', 'running')""",
                (now, now),
            )
            await db.execute(
                """UPDATE scans
                   SET status = CASE
                       WHEN status IN ('queued', 'pending') THEN 'stopped'
                       WHEN status = 'running' THEN 'stopping'
                       ELSE status
                   END,
                   updated_at = ?
                   WHERE status IN ('queued', 'pending', 'running')""",
                (now,),
            )
            await db.commit()
        finally:
            await db.close()

    await _with_retry(_run)


# --- Crawler and Learning ---


async def upsert_crawl_source(domain: str, source_url: str, trust_score: float = 0.5):
    db = await get_db()
    try:
        now = _utcnow_iso()
        cursor = await db.execute(
            "SELECT id, pages_crawled FROM crawl_sources WHERE domain = ?",
            (domain,),
        )
        existing = await cursor.fetchone()
        if existing:
            await db.execute(
                """UPDATE crawl_sources
                   SET source_url = ?, trust_score = ?, last_crawled_at = ?, pages_crawled = pages_crawled + 1
                   WHERE id = ?""",
                (source_url, float(trust_score), now, existing["id"]),
            )
            await db.commit()
            return str(existing["id"])
        source_id = str(uuid.uuid4())
        await db.execute(
            """INSERT INTO crawl_sources (id, domain, source_url, trust_score, status, last_crawled_at, pages_crawled, created_at)
               VALUES (?, ?, ?, ?, 'active', ?, 1, ?)""",
            (source_id, domain, source_url, float(trust_score), now, now),
        )
        await db.commit()
        return source_id
    finally:
        await db.close()


async def count_crawled_documents_today(domain: Optional[str] = None):
    db = await get_db()
    try:
        day_start = _utcnow().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        if domain:
            cursor = await db.execute(
                "SELECT COUNT(*) AS c FROM crawl_documents WHERE domain = ? AND fetched_at >= ?",
                (domain, day_start),
            )
        else:
            cursor = await db.execute(
                "SELECT COUNT(*) AS c FROM crawl_documents WHERE fetched_at >= ?",
                (day_start,),
            )
        row = await cursor.fetchone()
        return int(row["c"] if row else 0)
    finally:
        await db.close()


async def add_crawl_document(
    source_id: Optional[str],
    url: str,
    domain: str,
    depth: int,
    status: str,
    content_hash: str,
    content_type: str,
    content: str,
    lang: str,
    source_trust: float,
    expires_at: Optional[str] = None,
):
    db = await get_db()
    try:
        now = _utcnow_iso()
        cursor = await db.execute(
            "SELECT id FROM crawl_documents WHERE url = ? AND content_hash = ?",
            (url, content_hash),
        )
        existing = await cursor.fetchone()
        if existing:
            return str(existing["id"]), False
        doc_id = str(uuid.uuid4())
        await db.execute(
            """INSERT INTO crawl_documents
               (id, source_id, url, domain, depth, fetched_at, status, content_hash, content_type, content, lang, source_trust, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                doc_id,
                source_id,
                url,
                domain,
                depth,
                now,
                status,
                content_hash,
                content_type,
                content,
                lang,
                float(source_trust),
                expires_at,
            ),
        )
        await db.commit()
        return doc_id, True
    finally:
        await db.close()


async def add_crawl_extraction(
    document_id: str,
    source_url: str,
    fact: str,
    category: str,
    confidence: float,
    dedupe_hash: str,
    expires_at: Optional[str] = None,
):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id FROM crawl_extractions WHERE dedupe_hash = ?",
            (dedupe_hash,),
        )
        existing = await cursor.fetchone()
        if existing:
            return str(existing["id"]), False
        extraction_id = str(uuid.uuid4())
        await db.execute(
            """INSERT INTO crawl_extractions
               (id, document_id, source_url, fact, category, confidence, dedupe_hash, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                extraction_id,
                document_id,
                source_url,
                fact,
                category,
                float(confidence),
                dedupe_hash,
                _utcnow_iso(),
                expires_at,
            ),
        )
        await db.commit()
        return extraction_id, True
    finally:
        await db.close()


async def add_crawl_passage(
    *,
    document_id: str,
    source_url: str,
    domain: str,
    depth: int,
    passage_index: int,
    content: str,
    content_hash: str,
    expires_at: Optional[str] = None,
) -> tuple[Optional[str], bool]:
    """Insert a deduped crawl passage and (best-effort) index into FTS."""
    if not (content or "").strip():
        return None, False
    if not (content_hash or "").strip():
        return None, False

    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id FROM crawl_passages WHERE content_hash = ?",
            (content_hash,),
        )
        existing = await cursor.fetchone()
        if existing:
            return str(existing["id"]), False

        passage_id = str(uuid.uuid4())
        await db.execute(
            """INSERT INTO crawl_passages
               (id, document_id, source_url, domain, depth, passage_index, content, content_hash, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                passage_id,
                document_id,
                source_url,
                domain,
                int(depth),
                int(passage_index),
                content,
                content_hash,
                _utcnow_iso(),
                expires_at,
            ),
        )

        # Best-effort FTS insert (table may not exist on older SQLite builds).
        try:
            await db.execute(
                "INSERT INTO crawl_passages_fts (content, passage_id, source_url, domain) VALUES (?, ?, ?, ?)",
                (content, passage_id, source_url, domain),
            )
        except aiosqlite.OperationalError:
            pass

        await db.commit()
        return passage_id, True
    finally:
        await db.close()


async def add_crawl_passages_bulk(
    *,
    document_id: str,
    source_url: str,
    domain: str,
    depth: int,
    passages: list[str],
    expires_at: Optional[str] = None,
) -> int:
    """Insert multiple passages in one transaction (deduped by content_hash)."""
    if not passages:
        return 0
    db = await get_db()
    try:
        now = _utcnow_iso()
        inserted = 0
        for idx, content in enumerate(passages):
            text = (content or "").strip()
            if not text:
                continue
            content_hash = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
            passage_id = str(uuid.uuid4())
            cursor = await db.execute(
                """INSERT OR IGNORE INTO crawl_passages
                   (id, document_id, source_url, domain, depth, passage_index, content, content_hash, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    passage_id,
                    document_id,
                    source_url,
                    domain,
                    int(depth),
                    int(idx),
                    text,
                    content_hash,
                    now,
                    expires_at,
                ),
            )
            if int(getattr(cursor, "rowcount", 0) or 0) > 0:
                inserted += 1
                try:
                    await db.execute(
                        "INSERT INTO crawl_passages_fts (content, passage_id, source_url, domain) VALUES (?, ?, ?, ?)",
                        (text, passage_id, source_url, domain),
                    )
                except aiosqlite.OperationalError:
                    pass
        await db.commit()
        return inserted
    finally:
        await db.close()


async def list_recent_crawl_passages(limit: int = 200, domain: Optional[str] = None):
    db = await get_db()
    try:
        if domain:
            cursor = await db.execute(
                "SELECT * FROM crawl_passages WHERE domain = ? ORDER BY created_at DESC LIMIT ?",
                (domain, limit),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM crawl_passages ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def search_crawl_passages_fts(query: str, limit: int = 25, domain: Optional[str] = None):
    """Search crawled passages using FTS5 when available; fallback to LIKE/recency."""
    q = str(query or "").strip()
    db = await get_db()
    try:
        if q:
            try:
                if domain:
                    cursor = await db.execute(
                        """SELECT p.*, snippet(crawl_passages_fts, 0, '[', ']', '...', 12) AS snippet,
                                  bm25(crawl_passages_fts) AS score
                           FROM crawl_passages_fts
                           JOIN crawl_passages p ON p.id = crawl_passages_fts.passage_id
                           WHERE crawl_passages_fts MATCH ?
                             AND p.domain = ?
                           ORDER BY score
                           LIMIT ?""",
                        (q, domain, max(1, min(limit, 500))),
                    )
                else:
                    cursor = await db.execute(
                        """SELECT p.*, snippet(crawl_passages_fts, 0, '[', ']', '...', 12) AS snippet,
                                  bm25(crawl_passages_fts) AS score
                           FROM crawl_passages_fts
                           JOIN crawl_passages p ON p.id = crawl_passages_fts.passage_id
                           WHERE crawl_passages_fts MATCH ?
                           ORDER BY score
                           LIMIT ?""",
                        (q, max(1, min(limit, 500))),
                    )
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]
            except aiosqlite.OperationalError:
                # FTS unavailable, or malformed match query.
                pass

            # LIKE fallback for minimal utility when FTS isn't available.
            like = f"%{q[:80]}%"
            if domain:
                cursor = await db.execute(
                    """SELECT * FROM crawl_passages
                       WHERE domain = ? AND content LIKE ?
                       ORDER BY created_at DESC
                       LIMIT ?""",
                    (domain, like, max(1, min(limit, 500))),
                )
            else:
                cursor = await db.execute(
                    """SELECT * FROM crawl_passages
                       WHERE content LIKE ?
                       ORDER BY created_at DESC
                       LIMIT ?""",
                    (like, max(1, min(limit, 500))),
                )
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

        # Empty query: return recent passages.
        if domain:
            cursor = await db.execute(
                "SELECT * FROM crawl_passages WHERE domain = ? ORDER BY created_at DESC LIMIT ?",
                (domain, max(1, min(limit, 500))),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM crawl_passages ORDER BY created_at DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def list_crawl_sources(limit: int = 200):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM crawl_sources ORDER BY pages_crawled DESC, trust_score DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def list_recent_crawl_extractions(limit: int = 200):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM crawl_extractions ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def start_learning_run(stage: str, metrics: Optional[dict] = None):
    run_id = str(uuid.uuid4())
    db = await get_db()
    try:
        await db.execute(
            """INSERT INTO learning_runs (run_id, stage, status, metrics, started_at, finished_at)
               VALUES (?, ?, 'running', ?, ?, NULL)""",
            (run_id, stage, _json_dumps(metrics or {}), _utcnow_iso()),
        )
        await db.commit()
        return run_id
    finally:
        await db.close()


async def finish_learning_run(run_id: str, status: str, metrics: Optional[dict] = None):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE learning_runs SET status = ?, metrics = ?, finished_at = ? WHERE run_id = ?",
            (status, _json_dumps(metrics or {}), _utcnow_iso(), run_id),
        )
        await db.commit()
    finally:
        await db.close()


async def get_latest_learning_run(stage: Optional[str] = None):
    db = await get_db()
    try:
        if stage:
            cursor = await db.execute(
                "SELECT * FROM learning_runs WHERE stage = ? ORDER BY started_at DESC LIMIT 1",
                (stage,),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM learning_runs ORDER BY started_at DESC LIMIT 1"
            )
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


# --- Tool capabilities ---


async def upsert_tool_capability(tool_name: str, available: bool, details: Optional[dict] = None):
    db = await get_db()
    try:
        capability_id = hashlib.sha256(tool_name.encode("utf-8")).hexdigest()[:32]
        await db.execute(
            """INSERT INTO tool_capabilities (id, tool_name, available, checked_at, details)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(tool_name) DO UPDATE SET
                 available = excluded.available,
                 checked_at = excluded.checked_at,
                 details = excluded.details""",
            (
                capability_id,
                tool_name,
                1 if available else 0,
                _utcnow_iso(),
                _json_dumps(details or {}),
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def list_tool_capabilities(limit: int = 500):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM tool_capabilities ORDER BY checked_at DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_queue_stats():
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT type, status, COUNT(*) AS c FROM job_queue GROUP BY type, status"
        )
        rows = await cursor.fetchall()
        grouped: dict[str, dict[str, int]] = {}
        for row in rows:
            grouped.setdefault(row["type"], {})[row["status"]] = int(row["c"] or 0)
        return grouped
    finally:
        await db.close()
