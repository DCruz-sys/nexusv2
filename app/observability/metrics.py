"""Prometheus metrics helpers."""
from __future__ import annotations

try:
    from prometheus_client import Counter, Gauge, Histogram
except Exception:
    class _NoopMetric:
        def labels(self, *args, **kwargs):
            return self

        def inc(self, *_args, **_kwargs):
            return None

        def set(self, *_args, **_kwargs):
            return None

        def observe(self, *_args, **_kwargs):
            return None

    def Counter(*_args, **_kwargs):  # type: ignore
        return _NoopMetric()

    def Gauge(*_args, **_kwargs):  # type: ignore
        return _NoopMetric()

    def Histogram(*_args, **_kwargs):  # type: ignore
        return _NoopMetric()

HTTP_REQUESTS_TOTAL = Counter(
    "nexus_http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)
HTTP_REQUEST_LATENCY_SEC = Histogram(
    "nexus_http_request_latency_seconds",
    "HTTP request latency in seconds",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
NIM_CALL_LATENCY_SEC = Histogram(
    "nexus_nim_call_latency_seconds",
    "NIM model call latency in seconds",
    ["model", "operation"],
    buckets=(0.02, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
)
NIM_CALL_ERRORS_TOTAL = Counter(
    "nexus_nim_call_errors_total",
    "NIM model call errors",
    ["model", "operation", "code"],
)
QUEUE_DEPTH = Gauge(
    "nexus_queue_depth",
    "Queue depth grouped by type and status",
    ["job_type", "status"],
)
MEMORY_TOTAL_ITEMS = Gauge(
    "nexus_memory_total_items",
    "Total persisted memory items",
)
MEMORY_AVG_IMPORTANCE = Gauge(
    "nexus_memory_avg_importance",
    "Average memory item importance",
)


def update_queue_metrics(queue_stats: dict):
    for job_type, by_status in (queue_stats or {}).items():
        if not isinstance(by_status, dict):
            continue
        for status, count in by_status.items():
            QUEUE_DEPTH.labels(job_type=str(job_type), status=str(status)).set(float(count or 0))


def update_memory_metrics(memory_stats: dict):
    stats = memory_stats or {}
    MEMORY_TOTAL_ITEMS.set(float(stats.get("total_items", 0) or 0))
    MEMORY_AVG_IMPORTANCE.set(float(stats.get("avg_importance", 0.0) or 0.0))
