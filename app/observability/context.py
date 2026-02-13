"""Request/job correlation context helpers."""
from __future__ import annotations

from contextvars import ContextVar

_CORRELATION_ID: ContextVar[str] = ContextVar("correlation_id", default="")


def set_correlation_id(value: str) -> None:
    _CORRELATION_ID.set((value or "").strip())


def get_correlation_id() -> str:
    return _CORRELATION_ID.get().strip()
