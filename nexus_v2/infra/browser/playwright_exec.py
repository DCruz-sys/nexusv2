"""Playwright browser automation adapter (stub).

v2 supports browser-based validation tasks conceptually, but this adapter is
feature-flagged and not required for core tool execution.
"""

from __future__ import annotations


class PlaywrightNotEnabled(RuntimeError):
    pass


async def capture_screenshot(*_args, **_kwargs):
    raise PlaywrightNotEnabled("playwright_not_enabled")

