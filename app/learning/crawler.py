"""Daily web crawler and extraction pipeline for security knowledge ingestion."""
from __future__ import annotations

import asyncio
import hashlib
import html.parser
import ipaddress
import re
import socket
from collections import deque
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser
from urllib.request import urlopen

import httpx

from app.config import (
    CRAWL_BLOCK_PRIVATE_NETWORKS,
    CRAWL_FETCH_TIMEOUT_SEC,
    CRAWL_FOCUSED_ALLOW_SUBDOMAINS,
    CRAWL_FOCUSED_WWW_ALIAS,
    CRAWL_LINKS_PER_PAGE,
    CRAWL_LOW_CONF_TTL_DAYS,
    CRAWL_MAX_DEPTH,
    CRAWL_MAX_DOC_BYTES,
    CRAWL_MAX_PAGES_PER_DAY,
    CRAWL_MAX_PAGES_PER_DOMAIN,
    CRAWL_ROBOTS_CACHE,
    CRAWL_STORE_MAX_CHARS,
    CRAWL_MEDIUM_CONF_TTL_DAYS,
    KB_MAX_PASSAGES_PER_DOC,
    KB_PASSAGE_CHARS,
    KB_PASSAGE_OVERLAP_CHARS,
    LEARNING_SOURCE_BATCH_SIZE,
    LEARNING_SOURCE_MAX_CONSECUTIVE_FAILURES,
)
from app.database import (
    add_crawl_document,
    add_crawl_extraction,
    add_crawl_passages_bulk,
    add_learning_source_event,
    add_memory_audit_event,
    claim_learning_frontier,
    count_crawled_documents_today,
    count_learning_frontier,
    get_learning_source,
    get_crawler_policy_for_domain,
    list_crawl_sources,
    start_learning_run,
    finish_learning_run,
    update_learning_frontier_status,
    update_learning_source,
    upsert_learning_checkpoint,
    upsert_learning_frontier_url,
    upsert_crawl_source,
)

DEFAULT_SEEDS = [
    "https://owasp.org/",
    "https://attack.mitre.org/",
    "https://nvd.nist.gov/",
    "https://www.kali.org/tools/",
    "https://www.exploit-db.com/",
]

TRUSTED_DOMAINS = {
    "owasp.org": 0.95,
    "attack.mitre.org": 0.97,
    "nvd.nist.gov": 0.98,
    "kali.org": 0.94,
    "exploit-db.com": 0.86,
}

POISON_PATTERNS = [
    "ignore previous instructions",
    "system prompt",
    "developer message",
    "jailbreak",
]


class LinkExtractor(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: set[str] = set()

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.links.add(value.strip())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _utcnow().isoformat()


def _domain(url: str) -> str:
    return (urlparse(url).hostname or "").lower().strip(".")

def _strip_www(hostname: str) -> str:
    host = (hostname or "").strip().lower().strip(".")
    return host[4:] if host.startswith("www.") else host


def _allow_domain_for_run(
    domain: str,
    focus_hosts: set[str] | None,
    *,
    allow_subdomains: bool = True,
    www_alias: bool = True,
) -> bool:
    """Return True if this domain is allowed for the current crawl run.

    When focus_hosts is non-empty, we restrict to the focused host(s) and optionally their subdomains.
    """
    d = (domain or "").strip().lower().strip(".")
    if not d:
        return False
    if not focus_hosts:
        return True

    # Fast exact match.
    if d in focus_hosts:
        return True

    # Treat www.<host> and <host> as equivalent when enabled.
    if www_alias:
        d0 = _strip_www(d)
        if d0 in focus_hosts or f"www.{d0}" in focus_hosts:
            return True

    # Allow subdomains of any focused host.
    if allow_subdomains:
        for base in focus_hosts:
            b = (base or "").strip().lower().strip(".")
            if not b:
                continue
            if d.endswith(f".{b}"):
                return True

    return False


def _trust_for_domain(domain: str) -> float:
    if domain in TRUSTED_DOMAINS:
        return TRUSTED_DOMAINS[domain]
    for trusted, score in TRUSTED_DOMAINS.items():
        if domain.endswith(f".{trusted}"):
            return max(0.7, score - 0.05)
    return 0.55


def _is_domain_in_scope(domain: str, seed_domain: str, allow_subdomains: bool) -> bool:
    d = (domain or "").strip().lower().strip(".")
    seed = (seed_domain or "").strip().lower().strip(".")
    if not d or not seed:
        return False
    if d == seed:
        return True
    if allow_subdomains and d.endswith(f".{seed}"):
        return True
    return False


def _normalize_url(base_url: str, href: str) -> str:
    full = urljoin(base_url, href)
    parsed = urlparse(full)
    if parsed.scheme not in {"http", "https"}:
        return ""
    normalized = parsed._replace(fragment="").geturl()
    return normalized


def _is_public_ip(ip_text: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_text)
    except Exception:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _is_public_hostname(hostname: str) -> bool:
    host = (hostname or "").strip().lower()
    if not host:
        return False
    if host in {"localhost", "localhost.localdomain"}:
        return False
    if host.endswith(".local") or host.endswith(".internal"):
        return False
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return _is_public_ip(host)
    try:
        addresses = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:
        return False
    if not addresses:
        return False
    for info in addresses:
        ip_text = info[4][0]
        if not _is_public_ip(ip_text):
            return False
    return True


def _is_html(response: httpx.Response) -> bool:
    content_type = (response.headers.get("content-type") or "").lower()
    return "text/html" in content_type or "application/xhtml" in content_type


def _clean_text(html_text: str) -> str:
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", html_text)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:max(60000, int(CRAWL_STORE_MAX_CHARS))]


def _contains_poisoning(text: str) -> bool:
    lowered = text.lower()
    return any(pattern in lowered for pattern in POISON_PATTERNS)


def _categorize_fact(fact: str) -> str:
    l = fact.lower()
    if "cve-" in l:
        return "cve"
    if "owasp" in l:
        return "owasp"
    if "mitre" in l or "t10" in l:
        return "mitre"
    if any(tool in l for tool in ["nmap", "nikto", "sqlmap", "gobuster", "masscan"]):
        return "tooling"
    return "general"


def _extract_facts(text: str, max_facts: int = 12) -> list[tuple[str, float]]:
    facts: list[tuple[str, float]] = []
    cves = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.IGNORECASE)
    for cve in cves[:5]:
        facts.append((f"Reference detected: {cve.upper()}", 0.85))
    sentences = re.split(r"(?<=[.!?])\s+", text)
    keywords = ("vulnerability", "exploit", "mitre", "owasp", "rce", "xss", "sqli", "privilege escalation")
    for sentence in sentences:
        cleaned = re.sub(r"\s+", " ", sentence).strip()
        if len(cleaned) < 40:
            continue
        if any(keyword in cleaned.lower() for keyword in keywords):
            conf = 0.78 if "cve-" in cleaned.lower() else 0.68
            facts.append((cleaned[:280], conf))
        if len(facts) >= max_facts:
            break
    deduped = []
    seen = set()
    for fact, conf in facts:
        key = fact.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append((fact, conf))
    return deduped[:max_facts]


def _split_passages(
    text: str,
    *,
    passage_chars: int,
    overlap_chars: int,
    max_passages: int,
) -> list[str]:
    """Split long page text into overlapping passages for retrieval."""
    raw = re.sub(r"\s+", " ", (text or "")).strip()
    if not raw:
        return []
    size = max(200, int(passage_chars))
    overlap = max(0, min(int(overlap_chars), size - 50))
    step = max(50, size - overlap)

    out: list[str] = []
    start = 0
    while start < len(raw) and len(out) < max(1, int(max_passages)):
        end = min(len(raw), start + size)
        if end < len(raw):
            # Try to cut on whitespace for nicer passages.
            window = raw[start:end]
            cut = window.rfind(" ")
            if cut > max(80, int(size * 0.6)):
                end = start + cut
        chunk = raw[start:end].strip()
        if chunk:
            out.append(chunk)
        if end >= len(raw):
            break
        start += step
    return out


def _robots_allowed(url: str) -> bool:
    parsed = urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    rp = RobotFileParser()
    try:
        with urlopen(robots_url, timeout=min(CRAWL_FETCH_TIMEOUT_SEC, 10)) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
        if not content:
            return True
        rp.parse(content.splitlines())
        return rp.can_fetch("NexusPentestBot", url)
    except Exception:
        return True


def _robots_allowed_cached(url: str, cache: dict[str, RobotFileParser]) -> bool:
    """robots.txt policy with per-run cache to avoid re-downloading on every URL."""
    parsed = urlparse(url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    rp = cache.get(robots_url)
    if rp is None:
        rp = RobotFileParser()
        try:
            with urlopen(robots_url, timeout=min(CRAWL_FETCH_TIMEOUT_SEC, 10)) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
            if content:
                rp.parse(content.splitlines())
        except Exception:
            # Default allow on failures.
            pass
        cache[robots_url] = rp
    try:
        return rp.can_fetch("NexusPentestBot", url)
    except Exception:
        return True


async def run_crawl_cycle(
    seed_urls: list[str] | None = None,
    *,
    max_depth: int | None = None,
    max_pages_per_day: int | None = None,
    max_pages_per_domain: int | None = None,
    allow_subdomains: bool | None = None,
) -> dict:
    seed_urls = [s for s in (seed_urls or []) if isinstance(s, str) and s.startswith(("http://", "https://"))]
    focused = bool(seed_urls)

    HARD_MAX_DEPTH = 8
    HARD_MAX_PAGES_PER_DAY = 10000
    HARD_MAX_PAGES_PER_DOMAIN = 2000

    run_max_depth = CRAWL_MAX_DEPTH if max_depth is None else int(max_depth)
    run_max_depth = max(0, min(run_max_depth, HARD_MAX_DEPTH))
    run_max_pages_per_day = CRAWL_MAX_PAGES_PER_DAY if max_pages_per_day is None else int(max_pages_per_day)
    run_max_pages_per_day = max(1, min(run_max_pages_per_day, HARD_MAX_PAGES_PER_DAY))
    run_max_pages_per_domain = CRAWL_MAX_PAGES_PER_DOMAIN if max_pages_per_domain is None else int(max_pages_per_domain)
    run_max_pages_per_domain = max(1, min(run_max_pages_per_domain, HARD_MAX_PAGES_PER_DOMAIN))
    run_allow_subdomains = CRAWL_FOCUSED_ALLOW_SUBDOMAINS if allow_subdomains is None else bool(allow_subdomains)
    run_www_alias = bool(CRAWL_FOCUSED_WWW_ALIAS)

    focus_hosts: set[str] = set()
    if focused:
        for seed in seed_urls:
            host = _domain(seed)
            if not host:
                continue
            if run_www_alias:
                base = _strip_www(host)
                if base:
                    focus_hosts.add(base)
                    focus_hosts.add(f"www.{base}")
            focus_hosts.add(host)

    run_id = await start_learning_run(
        "crawl",
        {
            "seed_count": len(seed_urls or DEFAULT_SEEDS),
            "mode": "focused" if focused else "scheduled",
            "focus_domains": sorted(focus_hosts) if focused else [],
            "max_depth": run_max_depth,
            "max_pages_per_day": run_max_pages_per_day,
            "max_pages_per_domain": run_max_pages_per_domain,
            "allow_subdomains": run_allow_subdomains,
        },
    )
    fetched = 0
    extracted = 0
    skipped = 0
    errors = 0
    global_count = await count_crawled_documents_today()
    if global_count >= run_max_pages_per_day:
        await finish_learning_run(
            run_id,
            "completed",
            {"fetched": 0, "extracted": 0, "skipped": 0, "errors": 0, "reason": "daily_budget_reached"},
        )
        return {"fetched": 0, "extracted": 0, "skipped": 0, "errors": 0, "reason": "daily_budget_reached"}

    if focused:
        # Seed-only, focused crawl (no expansion to previously-known sources).
        seeds = list(dict.fromkeys(seed_urls))
    else:
        seeds = list(dict.fromkeys(DEFAULT_SEEDS))
        # add previously known sources with highest trust.
        for source in (await list_crawl_sources(limit=20)):
            url = source.get("source_url")
            if url:
                seeds.append(url)
        seeds = list(dict.fromkeys(seeds))

    queue = deque((url, 0) for url in seeds)
    seen = set()
    hostname_cache: dict[str, bool] = {}
    robots_cache: dict[str, RobotFileParser] = {}

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(float(CRAWL_FETCH_TIMEOUT_SEC), connect=10.0),
        follow_redirects=True,
        headers={"User-Agent": "NexusPentestBot/1.0 (+Kali Linux)"},
    ) as client:
        while queue and (global_count + fetched) < run_max_pages_per_day:
            url, depth = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            domain = _domain(url)
            if not domain:
                skipped += 1
                continue
            if not _allow_domain_for_run(
                domain,
                focus_hosts if focused else None,
                allow_subdomains=run_allow_subdomains,
                www_alias=run_www_alias,
            ):
                skipped += 1
                continue

            policy = await get_crawler_policy_for_domain(domain)
            if policy and int(policy.get("allow", 1) or 0) == 0:
                skipped += 1
                continue

            max_depth_effective = run_max_depth
            if policy and policy.get("max_depth") is not None:
                try:
                    max_depth_effective = int(policy["max_depth"])
                except Exception:
                    pass
            max_depth_effective = max(0, min(max_depth_effective, HARD_MAX_DEPTH))
            if depth > max_depth_effective:
                skipped += 1
                continue

            if CRAWL_BLOCK_PRIVATE_NETWORKS:
                if domain not in hostname_cache:
                    hostname_cache[domain] = await asyncio.to_thread(_is_public_hostname, domain)
                if not hostname_cache[domain]:
                    skipped += 1
                    continue

            daily_cap_effective = run_max_pages_per_domain
            if policy and policy.get("daily_cap") is not None:
                try:
                    daily_cap_effective = int(policy["daily_cap"])
                except Exception:
                    pass
            daily_cap_effective = max(1, min(daily_cap_effective, HARD_MAX_PAGES_PER_DOMAIN))
            if await count_crawled_documents_today(domain) >= daily_cap_effective:
                skipped += 1
                continue

            try:
                if CRAWL_ROBOTS_CACHE:
                    allowed = await asyncio.to_thread(_robots_allowed_cached, url, robots_cache)
                else:
                    allowed = await asyncio.to_thread(_robots_allowed, url)
                if not allowed:
                    skipped += 1
                    continue
            except Exception:
                pass

            try:
                response = await client.get(url)
            except Exception:
                errors += 1
                continue
            final_domain = _domain(str(response.url))
            if not _allow_domain_for_run(
                final_domain,
                focus_hosts if focused else None,
                allow_subdomains=run_allow_subdomains,
                www_alias=run_www_alias,
            ):
                skipped += 1
                continue
            if response.status_code >= 400:
                errors += 1
                continue
            if not _is_html(response):
                skipped += 1
                continue
            body = response.text
            if len(body.encode("utf-8", errors="ignore")) > CRAWL_MAX_DOC_BYTES:
                skipped += 1
                continue
            clean = _clean_text(body)
            if not clean or _contains_poisoning(clean):
                skipped += 1
                continue

            trust = _trust_for_domain(domain)
            if policy and policy.get("trust_floor") is not None:
                try:
                    if trust < float(policy["trust_floor"]):
                        skipped += 1
                        continue
                except Exception:
                    pass
            source_id = await upsert_crawl_source(domain, url, trust_score=trust)
            stored = clean[:max(1, int(CRAWL_STORE_MAX_CHARS))]
            content_hash = hashlib.sha256(stored.encode("utf-8", errors="ignore")).hexdigest()
            expires = None
            doc_id, inserted = await add_crawl_document(
                source_id=source_id,
                url=url,
                domain=domain,
                depth=depth,
                status="ok",
                content_hash=content_hash,
                content_type=response.headers.get("content-type", "text/html"),
                content=stored,
                lang="en",
                source_trust=trust,
                expires_at=expires,
            )
            if not inserted:
                skipped += 1
                continue
            fetched += 1

            # Create searchable passages for deep recall (best-effort, deduped).
            passages = _split_passages(
                stored,
                passage_chars=KB_PASSAGE_CHARS,
                overlap_chars=KB_PASSAGE_OVERLAP_CHARS,
                max_passages=KB_MAX_PASSAGES_PER_DOC,
            )
            await add_crawl_passages_bulk(
                document_id=doc_id,
                source_url=url,
                domain=domain,
                depth=depth,
                passages=passages,
                expires_at=None,
            )

            facts = _extract_facts(stored)
            for fact, confidence in facts:
                dedupe_hash = hashlib.sha256(fact.lower().encode("utf-8")).hexdigest()
                if confidence < 0.65:
                    expires_at = (datetime.now(timezone.utc) + timedelta(days=CRAWL_LOW_CONF_TTL_DAYS)).isoformat()
                elif confidence < 0.82:
                    expires_at = (datetime.now(timezone.utc) + timedelta(days=CRAWL_MEDIUM_CONF_TTL_DAYS)).isoformat()
                else:
                    expires_at = None

                extraction_id, created = await add_crawl_extraction(
                    document_id=doc_id,
                    source_url=url,
                    fact=fact,
                    category=_categorize_fact(fact),
                    confidence=confidence,
                    dedupe_hash=dedupe_hash,
                    expires_at=expires_at,
                )
                if not created:
                    continue
                extracted += 1

            extractor = LinkExtractor()
            try:
                extractor.feed(body)
            except Exception:
                extractor.links.clear()
            for href in list(extractor.links)[:max(1, int(CRAWL_LINKS_PER_PAGE))]:
                nxt = _normalize_url(url, href)
                if not nxt:
                    continue
                n_domain = _domain(nxt)
                if not n_domain:
                    continue
                if not _allow_domain_for_run(
                    n_domain,
                    focus_hosts if focused else None,
                    allow_subdomains=run_allow_subdomains,
                    www_alias=run_www_alias,
                ):
                    continue
                queue.append((nxt, depth + 1))

    metrics = {"fetched": fetched, "extracted": extracted, "skipped": skipped, "errors": errors}
    await finish_learning_run(run_id, "completed", metrics)
    await add_memory_audit_event(
        event_type="crawler_ingest",
        actor="crawler_worker",
        reason="daily_crawl_cycle",
        payload=metrics,
    )
    return metrics


async def run_learning_source_cycle(source_id: str, *, batch_size: int | None = None) -> dict:
    """Process one resumable crawl batch for a persistent learning source."""
    source = await get_learning_source(source_id)
    if not source:
        return {"ok": False, "reason": "source_not_found"}
    if not bool(source.get("enabled")):
        return {"ok": True, "reason": "source_disabled", "fetched": 0, "new_docs": 0, "frontier_added": 0, "errors": 0}

    run_limit = max(1, min(int(batch_size or LEARNING_SOURCE_BATCH_SIZE), 200))
    max_depth = max(0, min(int(source.get("max_depth") or 6), 8))
    allow_subdomains = bool(source.get("allow_subdomains"))
    source_domain = str(source.get("domain") or "").strip().lower()
    recrawl_interval_min = max(10, min(int(source.get("recrawl_interval_min") or 360), 10080))

    claimed = await claim_learning_frontier(source_id, limit=run_limit)
    if not claimed:
        next_run = (_utcnow() + timedelta(minutes=recrawl_interval_min)).isoformat()
        await update_learning_source(
            source_id,
            last_run_at=_utcnow_iso(),
            next_run_at=next_run,
        )
        await add_learning_source_event(source_id, "learning_frontier_exhausted", {"next_run_at": next_run})
        return {"ok": True, "reason": "frontier_exhausted", "fetched": 0, "new_docs": 0, "frontier_added": 0, "errors": 0}

    fetched = 0
    new_docs = 0
    frontier_added = 0
    errors = 0
    skipped = 0
    per_domain_docs = 0
    source_url = str(source.get("seed_url") or "")
    hostname_cache: dict[str, bool] = {}
    robots_cache: dict[str, RobotFileParser] = {}

    await add_learning_source_event(source_id, "learning_frontier_dequeued", {"count": len(claimed)})

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(float(CRAWL_FETCH_TIMEOUT_SEC), connect=10.0),
        follow_redirects=True,
        headers={"User-Agent": "NexusPentestBot/1.0 (+Kali Linux)"},
    ) as client:
        for item in claimed:
            frontier_id = str(item.get("id") or "")
            url = str(item.get("url") or "").strip()
            depth = int(item.get("depth") or 0)
            domain = _domain(url)
            if not frontier_id or not url:
                continue
            if depth > max_depth:
                skipped += 1
                await update_learning_frontier_status(frontier_id, status="skipped", last_error="max_depth_exceeded")
                continue
            if not _is_domain_in_scope(domain, source_domain, allow_subdomains):
                skipped += 1
                await update_learning_frontier_status(frontier_id, status="skipped", last_error="outside_seed_scope")
                continue
            if CRAWL_BLOCK_PRIVATE_NETWORKS:
                if domain not in hostname_cache:
                    hostname_cache[domain] = await asyncio.to_thread(_is_public_hostname, domain)
                if not hostname_cache[domain]:
                    skipped += 1
                    await update_learning_frontier_status(frontier_id, status="skipped", last_error="private_network")
                    continue

            try:
                if CRAWL_ROBOTS_CACHE:
                    allowed = await asyncio.to_thread(_robots_allowed_cached, url, robots_cache)
                else:
                    allowed = await asyncio.to_thread(_robots_allowed, url)
                if not allowed:
                    skipped += 1
                    await update_learning_frontier_status(frontier_id, status="skipped", last_error="robots_disallow")
                    continue
            except Exception:
                pass

            try:
                response = await client.get(url)
            except Exception as exc:
                errors += 1
                retry_at = (_utcnow() + timedelta(minutes=15)).isoformat()
                await update_learning_frontier_status(frontier_id, status="error", last_error=str(exc), next_retry_at=retry_at)
                continue

            final_url = str(response.url)
            final_domain = _domain(final_url)
            if not _is_domain_in_scope(final_domain, source_domain, allow_subdomains):
                skipped += 1
                await update_learning_frontier_status(frontier_id, status="skipped", last_error="redirected_out_of_scope")
                continue
            if response.status_code >= 400:
                errors += 1
                retry_at = (_utcnow() + timedelta(minutes=15)).isoformat()
                await update_learning_frontier_status(
                    frontier_id,
                    status="error",
                    last_error=f"http_{response.status_code}",
                    next_retry_at=retry_at,
                )
                continue
            if not _is_html(response):
                skipped += 1
                await update_learning_frontier_status(frontier_id, status="skipped", last_error="non_html")
                continue

            body = response.text
            if len(body.encode("utf-8", errors="ignore")) > CRAWL_MAX_DOC_BYTES:
                skipped += 1
                await update_learning_frontier_status(frontier_id, status="skipped", last_error="doc_too_large")
                continue
            clean = _clean_text(body)
            if not clean or _contains_poisoning(clean):
                skipped += 1
                await update_learning_frontier_status(frontier_id, status="skipped", last_error="empty_or_poisoned")
                continue

            trust = _trust_for_domain(final_domain or domain)
            source_row_id = await upsert_crawl_source(final_domain or domain, source_url, trust_score=trust)
            stored = clean[:max(1, int(CRAWL_STORE_MAX_CHARS))]
            content_hash = hashlib.sha256(stored.encode("utf-8", errors="ignore")).hexdigest()
            doc_id, inserted = await add_crawl_document(
                source_id=source_row_id,
                url=final_url or url,
                domain=final_domain or domain,
                depth=depth,
                status="ok",
                content_hash=content_hash,
                content_type=response.headers.get("content-type", "text/html"),
                content=stored,
                lang="en",
                source_trust=trust,
                expires_at=None,
            )
            fetched += 1
            if inserted:
                new_docs += 1
                per_domain_docs += 1

                passages = _split_passages(
                    stored,
                    passage_chars=KB_PASSAGE_CHARS,
                    overlap_chars=KB_PASSAGE_OVERLAP_CHARS,
                    max_passages=KB_MAX_PASSAGES_PER_DOC,
                )
                await add_crawl_passages_bulk(
                    document_id=doc_id,
                    source_url=final_url or url,
                    domain=final_domain or domain,
                    depth=depth,
                    passages=passages,
                    expires_at=None,
                )
                facts = _extract_facts(stored)
                for fact, confidence in facts:
                    dedupe_hash = hashlib.sha256(fact.lower().encode("utf-8")).hexdigest()
                    if confidence < 0.65:
                        expires_at = (_utcnow() + timedelta(days=CRAWL_LOW_CONF_TTL_DAYS)).isoformat()
                    elif confidence < 0.82:
                        expires_at = (_utcnow() + timedelta(days=CRAWL_MEDIUM_CONF_TTL_DAYS)).isoformat()
                    else:
                        expires_at = None
                    await add_crawl_extraction(
                        document_id=doc_id,
                        source_url=final_url or url,
                        fact=fact,
                        category=_categorize_fact(fact),
                        confidence=confidence,
                        dedupe_hash=dedupe_hash,
                        expires_at=expires_at,
                    )

            await update_learning_frontier_status(frontier_id, status="done", last_error=None, next_retry_at=None)

            if depth < max_depth and per_domain_docs <= int(source.get("max_pages_per_domain") or 300):
                extractor = LinkExtractor()
                try:
                    extractor.feed(body)
                except Exception:
                    extractor.links.clear()
                for href in list(extractor.links)[:max(1, int(CRAWL_LINKS_PER_PAGE))]:
                    nxt = _normalize_url(final_url or url, href)
                    if not nxt:
                        continue
                    nxt_domain = _domain(nxt)
                    if not _is_domain_in_scope(nxt_domain, source_domain, allow_subdomains):
                        continue
                    _id, created = await upsert_learning_frontier_url(
                        source_id=source_id,
                        url=nxt,
                        domain=nxt_domain,
                        depth=depth + 1,
                        priority=max(0, 100 - (depth + 1)),
                        discovered_from=final_url or url,
                    )
                    if created:
                        frontier_added += 1

    queued_remaining = await count_learning_frontier(source_id, status="queued")
    now = _utcnow()
    if queued_remaining > 0:
        next_run = (now + timedelta(seconds=30)).isoformat()
    else:
        next_run = (now + timedelta(minutes=recrawl_interval_min)).isoformat()
    previous_failures = int(source.get("consecutive_failures") or 0)
    failures = previous_failures + 1 if errors > 0 and new_docs == 0 else 0
    if failures >= LEARNING_SOURCE_MAX_CONSECUTIVE_FAILURES:
        next_run = (now + timedelta(minutes=max(recrawl_interval_min, 720))).isoformat()
        await add_learning_source_event(
            source_id,
            "learning_source_backoff",
            {"consecutive_failures": failures, "next_run_at": next_run},
        )
    await update_learning_source(
        source_id,
        last_run_at=now.isoformat(),
        next_run_at=next_run,
        consecutive_failures=failures,
    )
    checkpoint = {
        "last_run_at": now.isoformat(),
        "fetched": fetched,
        "new_docs": new_docs,
        "frontier_added": frontier_added,
        "queued_remaining": queued_remaining,
        "errors": errors,
        "skipped": skipped,
    }
    await upsert_learning_checkpoint(source_id, checkpoint)
    await add_learning_source_event(
        source_id,
        "learning_source_crawl_completed",
        checkpoint,
    )
    return {
        "ok": True,
        "source_id": source_id,
        "fetched": fetched,
        "new_docs": new_docs,
        "frontier_added": frontier_added,
        "queued_remaining": queued_remaining,
        "errors": errors,
        "skipped": skipped,
        "next_run_at": next_run,
    }
