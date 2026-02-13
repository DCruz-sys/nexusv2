"""Telemetry helpers for OpenTelemetry spans, Langfuse traces, and local metrics aggregation."""
from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:  # pragma: no cover - optional dependency
    from loguru import logger
except Exception:  # pragma: no cover
    import logging

    logger = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency
    from opentelemetry import trace
except Exception:  # pragma: no cover
    trace = None

try:  # pragma: no cover - optional dependency
    from langfuse import Langfuse
except Exception:  # pragma: no cover
    Langfuse = None

try:  # pragma: no cover - optional dependency
    from prometheus_client import Counter, Gauge
except Exception:  # pragma: no cover
    class _NoopMetric:
        def labels(self, *_args, **_kwargs):
            return self

        def inc(self, *_args, **_kwargs) -> None:
            return None

        def set(self, *_args, **_kwargs) -> None:
            return None

    def Counter(*_args, **_kwargs):  # type: ignore
        return _NoopMetric()

    def Gauge(*_args, **_kwargs):  # type: ignore
        return _NoopMetric()


AGENT_LOOP_COUNTER = Counter(
    "nexus_agent_loop_total",
    "Total ReACT loop events by step type",
    ["task_id", "agent", "step"],
)
AGENT_RETRY_TOTAL = Counter(
    "nexus_agent_retry_total",
    "Total retries requested by verification loop",
    ["task_id", "agent"],
)
GUARDRAIL_BLOCKS_TOTAL = Counter(
    "nexus_guardrail_blocks_total",
    "Total guardrail block events",
    ["reason"],
)
AGENT_TASK_COST_USD = Gauge(
    "nexus_agent_task_cost_usd",
    "Task cost in USD keyed by task and agent",
    ["task_id", "agent"],
)
AGENT_TASK_TOKENS_TOTAL = Gauge(
    "nexus_agent_task_tokens_total",
    "Task total tokens keyed by task and agent",
    ["task_id", "agent"],
)
AGENT_TASK_REWARD = Gauge(
    "nexus_agent_task_reward",
    "Task reward keyed by task and agent",
    ["task_id", "agent"],
)


@dataclass
class TelemetrySummary:
    """Aggregated telemetry values for a task/agent combination."""

    task_id: str
    agent: str
    cost_usd: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    reward: float = 0.0
    thought_count: int = 0
    action_count: int = 0
    verification_count: int = 0
    retry_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "agent": self.agent,
            "cost_usd": self.cost_usd,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "reward": self.reward,
            "thought_count": self.thought_count,
            "action_count": self.action_count,
            "verification_count": self.verification_count,
            "retry_count": self.retry_count,
        }


class _NoopSpan:
    def set_attribute(self, *_args, **_kwargs) -> None:
        return None

    def add_event(self, *_args, **_kwargs) -> None:
        return None


class TelemetryClient:
    """Thin wrappers around OpenTelemetry and Langfuse with fallback-safe APIs."""

    def __init__(self, service_name: str = "nexus") -> None:
        self.service_name = service_name
        self._tracer = trace.get_tracer(service_name) if trace else None
        self._langfuse = Langfuse() if Langfuse else None
        self._summaries: Dict[tuple[str, str], TelemetrySummary] = {}

    @contextmanager
    def span(self, name: str, *, attributes: Optional[Dict[str, Any]] = None):
        if self._tracer:
            with self._tracer.start_as_current_span(name) as span:
                for key, value in (attributes or {}).items():
                    span.set_attribute(key, value)
                yield span
            return
        yield _NoopSpan()

    def trace_event(
        self,
        *,
        task_id: str,
        name: str,
        input_payload: Optional[Dict[str, Any]] = None,
        output_payload: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not task_id or not self._langfuse or not hasattr(self._langfuse, "trace"):
            return
        try:
            trace_obj = self._langfuse.trace(id=task_id, name=name, metadata=metadata or {})
            trace_obj.event(name=name, input=input_payload or {}, output=output_payload or {}, metadata=metadata or {})
        except Exception as exc:  # pragma: no cover
            logger.debug(f"Telemetry Langfuse event failed: {exc}")

    def increment_loop_counter(self, *, task_id: str, agent: str, counter: str, amount: int = 1) -> None:
        summary = self._get_summary(task_id=task_id, agent=agent)
        AGENT_LOOP_COUNTER.labels(task_id=task_id, agent=agent, step=counter).inc(amount)

        if counter == "thought":
            summary.thought_count += amount
        elif counter == "action":
            summary.action_count += amount
        elif counter == "verification":
            summary.verification_count += amount
        elif counter == "retry":
            summary.retry_count += amount
            AGENT_RETRY_TOTAL.labels(task_id=task_id, agent=agent).inc(amount)

    def record_guardrail_block(self, *, reason: str) -> None:
        GUARDRAIL_BLOCKS_TOTAL.labels(reason=reason or "unknown").inc()

    def record_usage(
        self,
        *,
        task_id: str,
        agent: str,
        cost_usd: float = 0.0,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        total_tokens: int = 0,
        reward: Optional[float] = None,
    ) -> Dict[str, Any]:
        summary = self._get_summary(task_id=task_id, agent=agent)
        summary.cost_usd += float(cost_usd or 0.0)
        summary.prompt_tokens += int(prompt_tokens or 0)
        summary.completion_tokens += int(completion_tokens or 0)
        supplied_total = int(total_tokens or 0)
        summary.total_tokens += supplied_total or int(prompt_tokens or 0) + int(completion_tokens or 0)
        if reward is not None:
            summary.reward = float(reward)

        AGENT_TASK_COST_USD.labels(task_id=task_id, agent=agent).set(summary.cost_usd)
        AGENT_TASK_TOKENS_TOTAL.labels(task_id=task_id, agent=agent).set(summary.total_tokens)
        AGENT_TASK_REWARD.labels(task_id=task_id, agent=agent).set(summary.reward)
        return summary.to_dict()

    def get_task_totals(self, task_id: str) -> Dict[str, Any]:
        totals: Dict[str, Any] = {
            "task_id": task_id,
            "cost_usd": 0.0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "reward": 0.0,
            "agents": {},
        }
        for (row_task_id, agent), summary in self._summaries.items():
            if row_task_id != task_id:
                continue
            totals["cost_usd"] += summary.cost_usd
            totals["prompt_tokens"] += summary.prompt_tokens
            totals["completion_tokens"] += summary.completion_tokens
            totals["total_tokens"] += summary.total_tokens
            totals["reward"] += summary.reward
            totals["agents"][agent] = summary.to_dict()
        return totals

    def observe_phase(self, *, task_id: str, phase: str, status: str, started_at: float, details: Optional[Dict[str, Any]] = None) -> None:
        duration_ms = round((time.monotonic() - started_at) * 1000, 3)
        metadata = {"phase": phase, "status": status, "duration_ms": duration_ms, **(details or {})}
        self.trace_event(task_id=task_id, name=f"phase:{phase}", metadata=metadata, output_payload=details or {})

    def _get_summary(self, *, task_id: str, agent: str) -> TelemetrySummary:
        key = (task_id, agent)
        if key not in self._summaries:
            self._summaries[key] = TelemetrySummary(task_id=task_id, agent=agent)
        return self._summaries[key]


telemetry = TelemetryClient(service_name="nexus.core")
