"""NVIDIA NeMo Retriever (cloud) client for reranking passages via NIM Retrieval APIs."""
from __future__ import annotations

import asyncio
import time
import uuid
from typing import Optional

import httpx

from app.config import (
    KB_RERANK_MODEL,
    NIM_BACKOFF_BASE_MS,
    NIM_MAX_RETRIES,
    NIM_STATELESS_METADATA,
    NVIDIA_API_KEY,
    NVIDIA_RETRIEVAL_BASE_URL,
)
from app.observability.context import get_correlation_id


class NIMRetrievalClientError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int = 502):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class NIMRetrievalClient:
    def __init__(self):
        self.api_key = NVIDIA_API_KEY
        self.base_url = NVIDIA_RETRIEVAL_BASE_URL
        self.timeout = httpx.Timeout(45.0, connect=15.0)
        self._client: httpx.AsyncClient | None = None

    async def start(self):
        if self._client is not None:
            return
        self._client = httpx.AsyncClient(timeout=self.timeout)

    async def stop(self):
        if self._client is None:
            return
        await self._client.aclose()
        self._client = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            await self.start()
        assert self._client is not None
        return self._client

    def _headers(self) -> dict:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if NIM_STATELESS_METADATA:
            headers["X-Request-ID"] = str(uuid.uuid4())
            headers["X-Correlation-ID"] = get_correlation_id() or str(uuid.uuid4())
            headers["X-Nexus-Operation"] = "retrieval_rerank"
        return headers

    async def _post_with_retry(self, path: str, payload: dict) -> dict:
        if not (self.api_key or "").strip():
            raise NIMRetrievalClientError(
                code="nim_missing_api_key",
                message="NVIDIA_API_KEY is not configured.",
                status_code=503,
            )
        client = await self._get_client()
        retries = max(1, int(NIM_MAX_RETRIES))
        base_delay = max(10, int(NIM_BACKOFF_BASE_MS)) / 1000.0
        last_error: Exception | None = None

        for attempt in range(retries):
            try:
                resp = await client.post(
                    f"{self.base_url}{path}",
                    headers=self._headers(),
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                return data if isinstance(data, dict) else {"raw": data}
            except httpx.HTTPStatusError as exc:
                last_error = exc
                status = int(exc.response.status_code)
                # Don't retry non-429 client errors.
                if status < 500 and status != 429:
                    raise NIMRetrievalClientError(
                        code="nim_http_error",
                        message=f"NIM retrieval returned HTTP {status}.",
                        status_code=502,
                    ) from exc
            except httpx.TimeoutException as exc:
                last_error = exc
            except httpx.HTTPError as exc:
                last_error = exc

            if attempt < retries - 1:
                await asyncio.sleep(base_delay * (2 ** attempt))

        if isinstance(last_error, httpx.TimeoutException):
            raise NIMRetrievalClientError(
                code="nim_timeout",
                message="NIM retrieval request timed out after retries.",
                status_code=504,
            ) from last_error
        if isinstance(last_error, httpx.HTTPStatusError):
            status = int(last_error.response.status_code)
            raise NIMRetrievalClientError(
                code="nim_http_error",
                message=f"NIM retrieval failed after retries with HTTP {status}.",
                status_code=502,
            ) from last_error
        raise NIMRetrievalClientError(
            code="nim_unavailable",
            message="NIM retrieval is unavailable.",
            status_code=503,
        ) from last_error

    async def rerank(
        self,
        *,
        query: str,
        passages: list[str],
        model: Optional[str] = None,
    ) -> list[int]:
        """Return passage indices ordered from most to least relevant."""
        q = (query or "").strip()
        if not q or not passages:
            return list(range(len(passages)))

        payload = {
            "model": (model or KB_RERANK_MODEL),
            "query": {"text": q},
            "passages": [{"text": str(p)[:6000]} for p in passages],
            "truncate": "END",
        }
        data = await self._post_with_retry("/v1/retrieval/nvidia/reranking", payload)
        rankings = data.get("rankings")
        if not isinstance(rankings, list):
            return list(range(len(passages)))

        scored: list[tuple[float, int]] = []
        for row in rankings:
            if not isinstance(row, dict):
                continue
            try:
                idx = int(row.get("index"))
            except Exception:
                continue
            try:
                logit = float(row.get("logit", 0.0))
            except Exception:
                logit = 0.0
            if 0 <= idx < len(passages):
                scored.append((logit, idx))

        if not scored:
            return list(range(len(passages)))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [idx for _logit, idx in scored]


nim_retrieval_client = NIMRetrievalClient()
