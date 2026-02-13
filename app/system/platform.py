"""Platform detection helpers."""
from __future__ import annotations

from pathlib import Path


def is_linux() -> bool:
    try:
        import platform

        return platform.system().lower() == "linux"
    except Exception:
        return False


def is_kali_linux() -> bool:
    if not is_linux():
        return False
    os_release = Path("/etc/os-release")
    if not os_release.exists():
        return False
    try:
        content = os_release.read_text(encoding="utf-8", errors="ignore").lower()
    except Exception:
        return False
    return "id=kali" in content or "id_like=debian kali" in content or "kali" in content

