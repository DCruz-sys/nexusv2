"""Shared helpers for SQLite repositories (v2)."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str | None = None) -> str:
    value = uuid.uuid4().hex
    return f"{prefix}_{value}" if prefix else value


def json_dumps(value: Any) -> str:
    return json.dumps(value if value is not None else {}, default=str)


def json_loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default

