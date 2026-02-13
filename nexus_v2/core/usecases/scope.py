"""Engagement-scoped allowlist enforcement (v2)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class TargetInfo:
    raw: str
    host: str
    normalized: str
    is_ip: bool
    url: str


class TargetNotAllowedError(PermissionError):
    pass


def parse_target(target: str) -> TargetInfo:
    raw = (target or "").strip()
    if not raw:
        return TargetInfo(raw=raw, host="", normalized="", is_ip=False, url="")

    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = (parsed.hostname or raw).strip().lower().rstrip(".")
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except Exception:
        is_ip = False

    # Prefer a well-formed URL for URL-style tools.
    url = raw
    if "://" not in raw and host:
        url = f"http://{host}"
    return TargetInfo(raw=raw, host=host, normalized=host, is_ip=is_ip, url=url)


def match_domain_pattern(host: str, pattern: str) -> bool:
    """Exact or subdomain match; pattern may be URL or contain paths."""
    host_norm = (host or "").strip().lower().rstrip(".")
    pattern_norm = (pattern or "").strip().lower()
    if not host_norm or not pattern_norm:
        return False

    if "://" in pattern_norm:
        parsed = urlparse(pattern_norm)
        pattern_norm = (parsed.hostname or "").strip().lower()
    else:
        pattern_norm = pattern_norm.split("/", 1)[0].strip()

    # Strip accidental ports, leading dots, trailing dots.
    pattern_norm = pattern_norm.split(":", 1)[0].strip().lstrip(".").rstrip(".")
    if not pattern_norm:
        return False
    return host_norm == pattern_norm or host_norm.endswith(f".{pattern_norm}")


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
    if rule_type in {"ip", "cidr"}:
        return _match_ip_or_cidr(target.host, pattern)

    # fallback
    if "/" in pattern:
        return _match_ip_or_cidr(target.host, pattern)
    try:
        ipaddress.ip_address(pattern)
        return _match_ip_or_cidr(target.host, pattern)
    except Exception:
        return match_domain_pattern(target.host, pattern)


def require_target_allowed(target: str, rules: list[dict]) -> None:
    info = parse_target(target)
    if not info.host:
        raise TargetNotAllowedError("invalid_target")
    if not rules:
        raise TargetNotAllowedError("allowlist_empty")
    for rule in rules:
        if int(rule.get("enabled") or 0) != 1:
            continue
        if target_matches_rule(info, rule):
            return
    raise TargetNotAllowedError("no_allowlist_match")

