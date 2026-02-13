"""SQLite helpers + migration runner for Nexus v2."""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

from nexus_v2.config import Settings, get_settings


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _configure_connection(db: aiosqlite.Connection, *, settings: Settings) -> None:
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL;")
    await db.execute("PRAGMA synchronous=NORMAL;")
    await db.execute("PRAGMA foreign_keys=ON;")
    await db.execute(f"PRAGMA busy_timeout={max(100, int(settings.sqlite_busy_timeout_ms))};")


async def get_db(*, settings: Settings | None = None) -> aiosqlite.Connection:
    settings = settings or get_settings()
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    db = await aiosqlite.connect(str(settings.db_path))
    await _configure_connection(db, settings=settings)
    return db


async def _table_exists(db: aiosqlite.Connection, name: str) -> bool:
    cur = await db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
        (name,),
    )
    row = await cur.fetchone()
    return bool(row)


async def detect_schema(db: aiosqlite.Connection) -> str:
    """Return 'v2', 'v1', or 'unknown'."""
    if await _table_exists(db, "engagements") and await _table_exists(db, "runs"):
        return "v2"
    if await _table_exists(db, "scans") and await _table_exists(db, "scan_results"):
        return "v1"
    return "unknown"


def archive_v1_db(path: Path) -> Path:
    """Move v1 DB aside so v2 can initialize a clean schema."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    archived = path.with_name(f"{path.stem}.v1.{ts}{path.suffix}")
    archived.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(path), str(archived))
    return archived


async def apply_migrations(db: aiosqlite.Connection, *, settings: Settings) -> None:
    migrations_dir = Path(__file__).resolve().parent / "migrations"
    migrations = sorted(p for p in migrations_dir.glob("*.sql") if p.is_file())

    # Ensure schema_migrations exists even before the first migration.
    await db.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    await db.commit()

    cur = await db.execute("SELECT name FROM schema_migrations")
    applied = {str(row["name"]) for row in await cur.fetchall()}

    for path in migrations:
        name = path.name
        if name in applied:
            continue
        sql = path.read_text(encoding="utf-8")
        await db.executescript(sql)
        await db.execute(
            "INSERT INTO schema_migrations(name, applied_at) VALUES (?, ?)",
            (name, _utcnow_iso()),
        )
        await db.commit()


async def init_db(*, settings: Settings | None = None) -> dict:
    settings = settings or get_settings()
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)

    # Open current DB file (if any) to detect schema.
    db = await get_db(settings=settings)
    try:
        schema = await detect_schema(db)
    finally:
        await db.close()

    archived_path = None
    if schema == "v1" and settings.archive_v1_db and settings.db_path.exists():
        archived_path = str(archive_v1_db(settings.db_path))

    # Ensure v2 schema.
    db2 = await get_db(settings=settings)
    try:
        await apply_migrations(db2, settings=settings)
    finally:
        await db2.close()

    return {"db_path": str(settings.db_path), "archived_v1_db": archived_path}

