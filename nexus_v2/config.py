"""Nexus v2 configuration.

v2 is intentionally decoupled from the legacy `app/` package so it can be
developed side-by-side and cut over later.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return bool(default)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: str | None, default: int) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return int(default)


def _as_path(value: str | None, default: Path) -> Path:
    raw = (value or "").strip()
    return Path(raw) if raw else default


@dataclass(frozen=True)
class Settings:
    base_dir: Path
    db_path: Path
    artifacts_dir: Path
    archive_v1_db: bool
    sqlite_busy_timeout_ms: int

    # Runtime limits
    max_parallel: int
    tool_inline_max_bytes: int
    worker_heartbeat_sec: int

    # Catalog and schemas
    catalog_dir: Path
    schemas_dir: Path

    # Auth (reusing existing env names for convenience)
    auth_enabled: bool
    auth_jwt_secret: str
    auth_jwt_alg: str
    auth_access_token_min: int

    # NIM (optional; v2 can run without it for tool-only workflows)
    nvidia_api_key: str
    nvidia_base_url: str


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    base_dir = Path(__file__).resolve().parents[1]
    load_dotenv(dotenv_path=base_dir / ".env", override=False)

    db_path = _as_path(os.getenv("NEXUS_V2_DATABASE_PATH"), base_dir / ".runtime" / "data" / "nexus_v2.db")
    if not db_path.is_absolute():
        db_path = base_dir / db_path

    artifacts_dir = _as_path(os.getenv("NEXUS_V2_ARTIFACTS_DIR"), base_dir / "artifacts_v2")
    if not artifacts_dir.is_absolute():
        artifacts_dir = base_dir / artifacts_dir

    catalog_dir = _as_path(os.getenv("NEXUS_V2_CATALOG_DIR"), base_dir / "catalog_v2")
    if not catalog_dir.is_absolute():
        catalog_dir = base_dir / catalog_dir

    schemas_dir = _as_path(os.getenv("NEXUS_V2_SCHEMAS_DIR"), base_dir / "schemas_v2")
    if not schemas_dir.is_absolute():
        schemas_dir = base_dir / schemas_dir

    return Settings(
        base_dir=base_dir,
        db_path=db_path,
        artifacts_dir=artifacts_dir,
        archive_v1_db=_as_bool(os.getenv("NEXUS_V2_ARCHIVE_V1_DB"), True),
        sqlite_busy_timeout_ms=_as_int(os.getenv("NEXUS_V2_SQLITE_BUSY_TIMEOUT_MS"), 5000),
        max_parallel=max(1, _as_int(os.getenv("NEXUS_V2_MAX_PARALLEL"), 2)),
        tool_inline_max_bytes=max(1024, _as_int(os.getenv("NEXUS_V2_TOOL_INLINE_MAX_BYTES"), 50_000)),
        worker_heartbeat_sec=max(5, _as_int(os.getenv("NEXUS_V2_WORKER_HEARTBEAT_SEC"), 20)),
        catalog_dir=catalog_dir,
        schemas_dir=schemas_dir,
        auth_enabled=_as_bool(os.getenv("AUTH_ENABLED"), True),
        auth_jwt_secret=os.getenv("AUTH_JWT_SECRET", "change-me-in-production"),
        auth_jwt_alg=os.getenv("AUTH_JWT_ALG", "HS256"),
        auth_access_token_min=_as_int(os.getenv("AUTH_ACCESS_TOKEN_MIN"), 60),
        nvidia_api_key=os.getenv("NVIDIA_API_KEY", ""),
        nvidia_base_url=os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").rstrip("/"),
    )

