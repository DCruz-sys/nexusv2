"""Distillation pipeline: compress recent crawl facts into durable procedure cards."""
from __future__ import annotations

import hashlib
from collections import defaultdict

from app.ai.model_router import model_router
from app.ai.memory_manager import memory_manager
from app.config import MEMORY_EXTRACTION_MODEL
from app.database import (
    add_memory_audit_event,
    finish_learning_run,
    list_recent_crawl_extractions,
    start_learning_run,
)


def _cluster_by_category(items: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for item in items:
        cat = str(item.get("category") or "general").lower()
        grouped[cat].append(item)
    return grouped


def _heuristic_summary(category: str, items: list[dict]) -> str:
    lines = []
    seen = set()
    for item in items:
        fact = str(item.get("fact") or "").strip()
        if not fact:
            continue
        key = fact.lower()
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"- {fact}")
        if len(lines) >= 8:
            break
    heading = f"Procedure card ({category})"
    return f"{heading}\n" + "\n".join(lines)


async def _llm_summary(category: str, items: list[dict]) -> str:
    source = "\n".join(f"- {str(i.get('fact', ''))[:220]}" for i in items[:20])
    prompt = f"""Create a concise pentesting procedure card from these facts.
Category: {category}
Requirements:
- 5-8 bullet points
- actionable and technical
- no speculation

Facts:
{source}
"""
    try:
        result = await model_router.query(
            messages=[
                {"role": "system", "content": "You write concise security procedure cards."},
                {"role": "user", "content": prompt},
            ],
            force_model=MEMORY_EXTRACTION_MODEL,
            temperature=0.1,
        )
        text = str(result.get("response", "")).strip()
        return text[:2000] if text else ""
    except Exception:
        return ""


async def run_distillation(limit: int = 300, *, lineage: dict | None = None) -> dict:
    lineage_payload = lineage if isinstance(lineage, dict) else {}
    run_id = await start_learning_run("distill", {"limit": limit, "lineage": lineage_payload})
    items = await list_recent_crawl_extractions(limit=limit)
    if not items:
        metrics = {"cards": 0, "source_items": 0}
        await finish_learning_run(run_id, "completed", metrics)
        return metrics

    grouped = _cluster_by_category(items)
    cards = 0
    for category, rows in grouped.items():
        summary = await _llm_summary(category, rows)
        if not summary:
            summary = _heuristic_summary(category, rows)
        if not summary.strip():
            continue

        source_hash = hashlib.sha256(summary.lower().encode("utf-8")).hexdigest()[:20]
        await memory_manager.remember(
            content=summary,
            summary=summary[:220],
            memory_type="procedural",
            source_type="distillation",
            session_id=None,
            source_id=source_hash,
            metadata={
                "category": category,
                "source_count": len(rows),
                "distill_version": 2,
                **lineage_payload,
            },
            importance=0.74,
            confidence=0.82,
            reason="distillation_card",
        )
        cards += 1

    metrics = {"cards": cards, "source_items": len(items), "categories": len(grouped), "lineage": lineage_payload}
    await finish_learning_run(run_id, "completed", metrics)
    await add_memory_audit_event(
        event_type="distillation_run",
        actor="learning_worker",
        reason="scheduled_distillation",
        payload=metrics,
    )
    return metrics
