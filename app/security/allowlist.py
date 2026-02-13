"""Target allowlist scope enforcement."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

from app.config import TARGET_ENFORCEMENT_ENABLED
from app.database import add_memory_audit_event, list_target_rules


@dataclass
class TargetInfo:
    raw: str
    normalized: str
    host: str
    is_ip: bool


class TargetNotAllowedError(PermissionError):
    """Raised when an action is out of allowed scope."""


def parse_target(target: str) -> TargetInfo:
    raw = (target or "").strip()
    if not raw:
        return TargetInfo(raw=target, normalized="", host="", is_ip=False)

    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = (parsed.hostname or raw).strip().lower().rstrip(".")
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except Exception:
        is_ip = False

    normalized = host
    return TargetInfo(raw=raw, normalized=normalized, host=host, is_ip=is_ip)


def match_domain_pattern(host: str, pattern: str) -> bool:
    """Match a hostname against a domain allowlist pattern.

    Semantics mirror the target allowlist behavior:
    - exact domain match OR subdomain match
    - patterns may be pasted as full URLs or with paths
    """
    host_norm = (host or "").strip().lower().rstrip(".")
    pattern_norm = (pattern or "").strip().lower()
    if not host_norm or not pattern_norm:
        return False

    if "://" in pattern_norm:
        parsed = urlparse(pattern_norm)
        pattern_norm = (parsed.hostname or "").strip().lower()
    else:
        # Allow users to paste domains with paths, e.g. example.com/path
        pattern_norm = pattern_norm.split("/", 1)[0].strip()

    # Strip accidental ports in patterns.
    pattern_norm = pattern_norm.split(":", 1)[0].strip()
    pattern_norm = pattern_norm.lstrip(".").rstrip(".")
    if not pattern_norm:
        return False
    return host_norm == pattern_norm or host_norm.endswith(f".{pattern_norm}")


def match_any_domain_pattern(host: str, patterns: Iterable[str]) -> str | None:
    """Return the first matching pattern for host, else None."""
    for pattern in patterns:
        if match_domain_pattern(host, pattern):
            return pattern
    return None


def _match_domain(host: str, pattern: str) -> bool:
    return match_domain_pattern(host, pattern)


def _match_ip_or_cidr(host: str, pattern: str) -> bool:
    try:
        host_ip = ipaddress.ip_address(host)
    except Exception:
        return False
    try:
        if "/" in pattern:
            return host_ip in ipaddress.ip_network(pattern, strict=False)
        return host_ip == ipaddress.ip_address(pattern)
    except Exception:
        return False


def target_matches_rule(target: TargetInfo, rule: dict) -> bool:
    rule_type = str(rule.get("type", "")).strip().lower()
    pattern = str(rule.get("pattern", "")).strip()
    if not pattern:
        return False
    if rule_type == "domain":
        return match_domain_pattern(target.host, pattern)
    if rule_type == "ip":
        return _match_ip_or_cidr(target.host, pattern)
    if rule_type == "cidr":
        return _match_ip_or_cidr(target.host, pattern)
    # fallback auto mode: decide from pattern shape.
    if "/" in pattern:
        return _match_ip_or_cidr(target.host, pattern)
    try:
        ipaddress.ip_address(pattern)
        return _match_ip_or_cidr(target.host, pattern)
    except Exception:
        return _match_domain(target.host, pattern)


async def is_target_allowed(target: str) -> tuple[bool, str]:
    target_info = parse_target(target)
    if not TARGET_ENFORCEMENT_ENABLED:
        return True, "enforcement_disabled"
    if not target_info.host:
        return False, "invalid_target"

    rules = await list_target_rules(enabled_only=True)
    if not rules:
        return False, "allowlist_empty"

    for rule in rules:
        if target_matches_rule(target_info, rule):
            return True, f"matched_rule:{rule.get('id')}"
    return False, "no_allowlist_match"


async def require_target_allowed(target: str, actor: str = "system", reason: str = "scope_check"):
    allowed, detail = await is_target_allowed(target)
    await add_memory_audit_event(
        event_type="target_resolution",
        actor=actor,
        reason=reason,
        payload={
            "target": target,
            "allowed": allowed,
            "detail": detail,
        },
    )
    if not allowed:
        raise TargetNotAllowedError(
            f"Target '{target}' is outside allowed scope ({detail}). Add it to /api/targets first."
        )
