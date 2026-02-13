#!/usr/bin/env python3
"""
Frontend smoke QA using Selenium.

This is intentionally lightweight and validates the main user flows:
- Login modal (admin/admin)
- Targets allowlist (add scanme.nmap.org)
- New scan (quick scanme.nmap.org) and wait for completion
- Chat message send/receive
"""

from __future__ import annotations

import sys
import time
import urllib.request

from selenium import webdriver
from selenium.common.exceptions import NoSuchDriverException, TimeoutException, WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


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

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1280,900")
    options.binary_location = "/usr/bin/chromium"

    try:
        # Selenium Manager will try to fetch a matching driver. Some locked-down networks
        # block access to the Chrome-for-Testing metadata endpoint.
        driver = webdriver.Chrome(options=options)
    except (NoSuchDriverException, WebDriverException) as exc:
        print(f"[SKIP] unable to start webdriver: {exc}", file=sys.stderr)
        return 3

    wait = WebDriverWait(driver, 30)

    try:
        driver.get(BASE_URL)

        # Login modal.
        wait.until(EC.visibility_of_element_located((By.ID, "auth-modal")))
        driver.find_element(By.ID, "auth-username").clear()
        driver.find_element(By.ID, "auth-username").send_keys("admin")
        driver.find_element(By.ID, "auth-password").send_keys("admin")
        driver.find_element(By.XPATH, "//button[contains(., 'Sign in')]").click()
        wait.until(EC.invisibility_of_element_located((By.ID, "auth-modal")))

        # Targets page.
        driver.find_element(By.CSS_SELECTOR, ".nav-item[data-page='targets']").click()
        wait.until(EC.presence_of_element_located((By.ID, "targets-list")))
        pat = driver.find_element(By.ID, "target-rule-pattern")
        pat.clear()
        pat.send_keys("scanme.nmap.org")
        driver.find_element(By.CSS_SELECTOR, "#page-targets button.btn.btn-primary").click()
        time.sleep(1.0)

        # New scan: allowlist badge should resolve to allowlisted (or we can quick-add).
        driver.find_element(By.CSS_SELECTOR, ".nav-item[data-page='new-scan']").click()
        wait.until(EC.presence_of_element_located((By.ID, "scan-target")))
        tgt = driver.find_element(By.ID, "scan-target")
        tgt.clear()
        tgt.send_keys("http://scanme.nmap.org/")
        wait.until(EC.visibility_of_element_located((By.ID, "allowlist-row")))
        time.sleep(1.0)
        badge = driver.find_element(By.ID, "allowlist-badge").text.strip().lower()
        if "blocked" in badge:
            driver.find_element(By.ID, "allowlist-add-btn").click()
            time.sleep(1.0)
            badge = driver.find_element(By.ID, "allowlist-badge").text.strip().lower()
        if "allowlisted" not in badge:
            raise RuntimeError(f"allowlist_badge_unexpected:{badge}")

        # Launch scan.
        driver.find_element(By.XPATH, "//button[contains(., 'Launch Scan')]").click()
        wait.until(EC.presence_of_element_located((By.ID, "active-scans-list")))

        # Wait for scan completed badge in active scans.
        WebDriverWait(driver, 160).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "#active-scans-list .badge-completed"))
        )

        # Chat.
        driver.find_element(By.CSS_SELECTOR, ".nav-item[data-page='chat']").click()
        wait.until(EC.presence_of_element_located((By.ID, "chat-input")))
        chat = driver.find_element(By.ID, "chat-input")
        chat.send_keys("Explain SQL injection in one sentence.")
        driver.find_element(By.ID, "chat-send-btn").click()

        # Wait for assistant stream to finish and content to appear.
        time.sleep(1.5)
        WebDriverWait(driver, 25).until(
            lambda d: len(d.find_elements(By.CSS_SELECTOR, "#chat-messages .chat-msg.assistant .msg-content")) >= 1
        )
        last = driver.find_elements(By.CSS_SELECTOR, "#chat-messages .chat-msg.assistant .msg-content")[-1].text.strip()
        if len(last) < 20:
            raise RuntimeError("chat_response_too_short")

        print("[PASS] frontend smoke flows")
        return 0
    except TimeoutException as exc:
        print(f"[FAIL] timeout: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    finally:
        driver.quit()


if __name__ == "__main__":
    raise SystemExit(main())
