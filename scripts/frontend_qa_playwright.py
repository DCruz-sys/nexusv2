#!/usr/bin/env python3
"""
Frontend smoke QA using Playwright.

Assumes the server is running on http://127.0.0.1:8000.
This script drives the UI like a user: login, targets allowlist, start scan, and wait for completion.
"""

from __future__ import annotations

import sys
import time
import urllib.request

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


BASE_URL = "http://127.0.0.1:8000"


def wait_for_health(timeout_sec: int = 20) -> None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{BASE_URL}/api/health", timeout=2) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.4)
    raise RuntimeError("server_not_healthy")


def main() -> int:
    wait_for_health()

    try:
        pw = sync_playwright()
        p = pw.__enter__()
    except Exception as exc:
        print(f"[SKIP] playwright driver unavailable in this environment: {exc}", file=sys.stderr)
        return 3

    browser = p.chromium.launch(
        headless=True,
        executable_path="/usr/bin/chromium",
        args=["--no-sandbox"],
    )
    ctx = browser.new_context()
    page = ctx.new_page()

    try:
        page.goto(BASE_URL, wait_until="domcontentloaded", timeout=15_000)
        page.wait_for_selector("#auth-modal", state="visible", timeout=10_000)
        page.fill("#auth-username", "admin")
        page.fill("#auth-password", "admin")
        page.click("button:has-text('Sign in')")
        page.wait_for_selector("#auth-modal", state="hidden", timeout=10_000)

        # Targets page: ensure scanme allowlist exists.
        page.click(".nav-item[data-page='targets']")
        page.wait_for_selector("#targets-list", timeout=10_000)
        page.fill("#target-rule-pattern", "scanme.nmap.org")
        page.click("#page-targets button:has-text('Add')")
        time.sleep(0.8)

        # New scan: ensure allowlist badge resolves; quick scan.
        page.click(".nav-item[data-page='new-scan']")
        page.wait_for_selector("#scan-target", timeout=10_000)
        page.fill("#scan-target", "http://scanme.nmap.org/")
        page.wait_for_selector("#allowlist-row", state="visible", timeout=10_000)
        time.sleep(0.8)
        badge = (page.inner_text("#allowlist-badge") or "").strip().lower()
        if "blocked" in badge:
            page.click("#allowlist-add-btn")
            time.sleep(0.8)
            badge = (page.inner_text("#allowlist-badge") or "").strip().lower()
        if "allowlisted" not in badge:
            raise RuntimeError(f"allowlist_badge_unexpected:{badge}")

        page.select_option("#scan-type", "quick")
        page.click("button:has-text('Launch Scan')")

        # Active scans: wait for completion.
        page.wait_for_selector("#active-scans-list .card", timeout=15_000)
        page.wait_for_selector("#active-scans-list .badge-completed", timeout=120_000)

        # Chat: send a message, wait for assistant response bubble.
        page.click(".nav-item[data-page='chat']")
        page.wait_for_selector("#chat-input", timeout=10_000)
        page.fill("#chat-input", "Explain SQL injection in one sentence.")
        page.click("#chat-send-btn")
        page.wait_for_selector("#chat-messages .chat-msg.assistant .msg-content", timeout=20_000)

        return 0
    except PlaywrightTimeoutError as exc:
        print(f"[FAIL] playwright_timeout: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            ctx.close()
        except Exception:
            pass
        try:
            browser.close()
        except Exception:
            pass
        try:
            pw.__exit__(None, None, None)
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
