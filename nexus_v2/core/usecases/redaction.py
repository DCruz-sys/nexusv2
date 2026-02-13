"""Redaction utilities for logs/events/artifacts (v2)."""

from __future__ import annotations

import re


_SENSITIVE_PATTERNS: list[re.Pattern] = [
    re.compile(r"(api[_-]?key\s*[:=]\s*)([A-Za-z0-9_\-]{6,})", re.IGNORECASE),
    re.compile(r"(authorization\s*:\s*bearer\s+)([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE),
    re.compile(r"(password\s*[:=]\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(secret\s*[:=]\s*)(\S+)", re.IGNORECASE),
]


def redact_text(text: str) -> str:
    value = str(text or "")
    for pattern in _SENSITIVE_PATTERNS:
        value = pattern.sub(r"\1[REDACTED]", value)
    return value

