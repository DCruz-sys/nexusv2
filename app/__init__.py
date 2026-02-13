"""NexusPenTest package bootstrap."""

from __future__ import annotations

import asyncio
import logging

LOGGER = logging.getLogger(__name__)

UVLOOP_AVAILABLE = False
UVLOOP_CONFIGURED = False


def _configure_event_loop_policy() -> None:
    """Apply uvloop policy early so async DB operations remain responsive."""
    global UVLOOP_AVAILABLE, UVLOOP_CONFIGURED
    try:
        import uvloop  # type: ignore
    except Exception as exc:
        LOGGER.warning(
            "uvloop is unavailable; using default asyncio loop. "
            "If database startup hangs, install uvloop. reason=%s",
            exc,
        )
        UVLOOP_AVAILABLE = False
        UVLOOP_CONFIGURED = False
        return

    UVLOOP_AVAILABLE = True
    try:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        UVLOOP_CONFIGURED = True
    except Exception as exc:
        UVLOOP_CONFIGURED = False
        LOGGER.warning("Failed to configure uvloop event loop policy: %s", exc)


_configure_event_loop_policy()
