"""Optional native accelerators (Rust/Go) invoked via subprocess JSON RPC."""
import asyncio
import json
import time
from pathlib import Path
from typing import Optional

from app.config import (
    ACCELERATOR_TIMEOUT_MS,
    ENABLE_NATIVE_ACCELERATORS,
    MEMORY_DECAY_DAYS,
    MEMORY_MIN_SCORE,
    MEMORY_RANKER_BIN,
    SWARM_MAX_PARALLEL,
    SWARM_PLANNER_BIN,
)

_binary_resolution_cache: dict[str, tuple[float, Optional[Path]]] = {}
_CACHE_TTL_SEC = 30


def _resolve_binary(binary_path: str) -> Optional[Path]:
    now = time.time()
    cached = _binary_resolution_cache.get(binary_path)
    if cached and now - cached[0] < _CACHE_TTL_SEC:
        return cached[1]

    if not binary_path:
        _binary_resolution_cache[binary_path] = (now, None)
        return None
    path = Path(binary_path)
    if path.exists() and path.is_file():
        _binary_resolution_cache[binary_path] = (now, path)
        return path
    exe_fallback = path.with_suffix(path.suffix + ".exe") if path.suffix else Path(str(path) + ".exe")
    if exe_fallback.exists() and exe_fallback.is_file():
        _binary_resolution_cache[binary_path] = (now, exe_fallback)
        return exe_fallback
    _binary_resolution_cache[binary_path] = (now, None)
    return None


async def _run_json_binary(binary_path: str, payload: dict, timeout_ms: int = ACCELERATOR_TIMEOUT_MS) -> Optional[dict]:
    """Run a local binary that reads JSON stdin and writes JSON stdout."""
    path = _resolve_binary(binary_path)
    if not path:
        return None

    try:
        proc = await asyncio.create_subprocess_exec(
            str(path),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception:
        return None

    try:
        stdout, _stderr = await asyncio.wait_for(
            proc.communicate(input=json.dumps(payload).encode("utf-8")),
            timeout=max(0.2, timeout_ms / 1000.0),
        )
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
        return None

    if proc.returncode != 0:
        return None

    try:
        parsed = json.loads(stdout.decode("utf-8", errors="replace"))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


async def rank_memory_candidates(query: str, candidates: list[dict], limit: int) -> Optional[list[dict]]:
    """Return ranked candidate list from Rust accelerator when available."""
    if not ENABLE_NATIVE_ACCELERATORS:
        return None
    payload = {
        "query": query,
        "limit": int(limit),
        "min_score": float(MEMORY_MIN_SCORE),
        "decay_days": int(MEMORY_DECAY_DAYS),
        "candidates": candidates,
    }
    response = await _run_json_binary(MEMORY_RANKER_BIN, payload)
    if not response:
        return None
    results = response.get("results")
    if not isinstance(results, list):
        return None
    cleaned = []
    for row in results:
        if not isinstance(row, dict):
            continue
        memory_id = str(row.get("id", "")).strip()
        if not memory_id:
            continue
        try:
            score = float(row.get("score", 0.0))
        except Exception:
            score = 0.0
        cleaned.append({"id": memory_id, "score": score})
    return cleaned or None


async def plan_swarm_waves(tasks: list[dict], max_parallel: int = SWARM_MAX_PARALLEL) -> Optional[list[list[str]]]:
    """Return execution waves from Go planner when available."""
    if not ENABLE_NATIVE_ACCELERATORS:
        return None
    payload = {"tasks": tasks, "max_parallel": int(max_parallel)}
    response = await _run_json_binary(SWARM_PLANNER_BIN, payload)
    if not response:
        return None
    waves = response.get("waves")
    if not isinstance(waves, list):
        return None
    normalized: list[list[str]] = []
    for wave in waves:
        if not isinstance(wave, list):
            continue
        normalized.append([str(item) for item in wave if str(item).strip()])
    return normalized or None
