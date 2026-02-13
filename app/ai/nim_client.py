"""NVIDIA NIM API async client with pooling, retries, and circuit breaking."""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import AsyncGenerator

import httpx

from app.config import (
    MODELS,
    NIM_BACKOFF_BASE_MS,
    NIM_CIRCUIT_FAIL_THRESHOLD,
    NIM_CIRCUIT_RESET_SEC,
    NIM_MAX_RETRIES,
    NVIDIA_API_KEY,
    NVIDIA_BASE_URL,
    NIM_STATELESS_METADATA,
)
from app.observability.context import get_correlation_id
from app.observability.metrics import NIM_CALL_ERRORS_TOTAL, NIM_CALL_LATENCY_SEC


class NIMClientError(RuntimeError):
    """Structured NIM client error."""

    def __init__(self, code: str, message: str, status_code: int = 502):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class NIMClient:
    """Async client for NVIDIA NIM API."""

    def __init__(self):
        self.api_key = NVIDIA_API_KEY
        self.base_url = NVIDIA_BASE_URL
        self.timeout = httpx.Timeout(120.0, connect=15.0)
        self._client: httpx.AsyncClient | None = None
        self._failures = 0
        self._circuit_open_until = 0.0

    def _get_headers(self, operation: str) -> dict:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if NIM_STATELESS_METADATA:
            headers["X-Request-ID"] = str(uuid.uuid4())
            headers["X-Correlation-ID"] = get_correlation_id() or str(uuid.uuid4())
            headers["X-Nexus-Operation"] = operation
        return headers

    def _resolve_model(self, model_key: str) -> str:
        return MODELS.get(model_key, model_key)

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

    def _check_circuit(self, model: str, operation: str):
        now = time.time()
        if now < self._circuit_open_until:
            wait_sec = max(1, int(self._circuit_open_until - now))
            raise NIMClientError(
                code="nim_circuit_open",
                message=f"NIM circuit is open; retry after {wait_sec}s.",
                status_code=503,
            )

    def _register_failure(self, model: str, operation: str, code: str):
        self._failures += 1
        NIM_CALL_ERRORS_TOTAL.labels(model=model, operation=operation, code=code).inc()
        if self._failures >= max(1, NIM_CIRCUIT_FAIL_THRESHOLD):
            self._circuit_open_until = time.time() + max(1, NIM_CIRCUIT_RESET_SEC)

    def _register_success(self):
        self._failures = 0
        self._circuit_open_until = 0.0

    async def _post_with_retry(self, endpoint: str, payload: dict, model: str, operation: str) -> httpx.Response:
        if not (self.api_key or "").strip():
            raise NIMClientError(
                code="nim_missing_api_key",
                message="NVIDIA_API_KEY is not configured.",
                status_code=503,
            )
        self._check_circuit(model=model, operation=operation)
        retries = max(1, int(NIM_MAX_RETRIES))
        base_delay = max(10, int(NIM_BACKOFF_BASE_MS)) / 1000.0
        client = await self._get_client()
        last_error: Exception | None = None

        for attempt in range(retries):
            start = time.perf_counter()
            try:
                response = await client.post(
                    f"{self.base_url}{endpoint}",
                    headers=self._get_headers(operation=operation),
                    json=payload,
                )
                response.raise_for_status()
                self._register_success()
                NIM_CALL_LATENCY_SEC.labels(model=model, operation=operation).observe(
                    max(0.0, time.perf_counter() - start)
                )
                return response
            except httpx.HTTPStatusError as exc:
                status_code = int(exc.response.status_code)
                code = "nim_http_error"
                self._register_failure(model=model, operation=operation, code=code)
                if status_code < 500 and status_code != 429:
                    raise NIMClientError(
                        code=code,
                        message=f"NIM returned HTTP {status_code}.",
                        status_code=502,
                    ) from exc
                last_error = exc
            except httpx.TimeoutException as exc:
                code = "nim_timeout"
                self._register_failure(model=model, operation=operation, code=code)
                last_error = exc
            except httpx.HTTPError as exc:
                code = "nim_transport_error"
                self._register_failure(model=model, operation=operation, code=code)
                last_error = exc

            if attempt < retries - 1:
                await asyncio.sleep(base_delay * (2 ** attempt))

        if isinstance(last_error, NIMClientError):
            raise last_error
        if isinstance(last_error, httpx.HTTPStatusError):
            status = int(last_error.response.status_code)
            raise NIMClientError(
                code="nim_http_error",
                message=f"NIM call failed after retries with HTTP {status}.",
                status_code=502,
            ) from last_error
        if isinstance(last_error, httpx.TimeoutException):
            raise NIMClientError(
                code="nim_timeout",
                message="NIM request timed out after retries.",
                status_code=504,
            ) from last_error
        raise NIMClientError(
            code="nim_unavailable",
            message="NIM service unavailable.",
            status_code=503,
        ) from last_error

    async def chat_completion(
        self,
        messages: list,
        model_key: str = "llama-3.1-70b",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        metadata: dict | None = None,
    ) -> str:
        """Non-streaming chat completion."""
        model = self._resolve_model(model_key)
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if metadata:
            payload["metadata"] = metadata
        resp = await self._post_with_retry(
            endpoint="/chat/completions",
            payload=payload,
            model=model,
            operation="chat_completion",
        )
        data = resp.json()
        choices = data.get("choices") or []
        if not choices:
            raise NIMClientError(code="nim_empty_response", message="NIM returned empty completion.")
        message = choices[0].get("message") or {}
        return str(message.get("content") or "")

    async def chat_completion_stream(
        self,
        messages: list,
        model_key: str = "llama-3.1-70b",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        metadata: dict | None = None,
    ) -> AsyncGenerator[str, None]:
        """Streaming chat completion - yields tokens as they arrive."""
        model = self._resolve_model(model_key)
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }
        if metadata:
            payload["metadata"] = metadata
        if not (self.api_key or "").strip():
            raise NIMClientError(
                code="nim_missing_api_key",
                message="NVIDIA_API_KEY is not configured.",
                status_code=503,
            )
        self._check_circuit(model=model, operation="chat_stream")
        client = await self._get_client()
        retries = max(1, int(NIM_MAX_RETRIES))
        base_delay = max(10, int(NIM_BACKOFF_BASE_MS)) / 1000.0
        last_error: Exception | None = None

        for attempt in range(retries):
            start = time.perf_counter()
            try:
                async with client.stream(
                    "POST",
                    f"{self.base_url}/chat/completions",
                    headers=self._get_headers(operation="chat_stream"),
                    json=payload,
                ) as resp:
                    resp.raise_for_status()
                    self._register_success()
                    NIM_CALL_LATENCY_SEC.labels(model=model, operation="chat_stream").observe(
                        max(0.0, time.perf_counter() - start)
                    )
                    async for line in resp.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        data_str = line[6:]
                        if data_str.strip() == "[DONE]":
                            return
                        try:
                            data = json.loads(data_str)
                            delta = data.get("choices", [{}])[0].get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                yield content
                        except json.JSONDecodeError:
                            continue
                return
            except httpx.HTTPStatusError as exc:
                code = "nim_http_error"
                self._register_failure(model=model, operation="chat_stream", code=code)
                if int(exc.response.status_code) < 500 and int(exc.response.status_code) != 429:
                    raise NIMClientError(code=code, message=f"NIM returned HTTP {exc.response.status_code}.") from exc
                last_error = exc
            except httpx.TimeoutException as exc:
                code = "nim_timeout"
                self._register_failure(model=model, operation="chat_stream", code=code)
                last_error = exc
            except httpx.HTTPError as exc:
                code = "nim_transport_error"
                self._register_failure(model=model, operation="chat_stream", code=code)
                last_error = exc

            if attempt < retries - 1:
                await asyncio.sleep(base_delay * (2 ** attempt))

        if isinstance(last_error, httpx.TimeoutException):
            raise NIMClientError(code="nim_timeout", message="NIM stream timed out after retries.") from last_error
        if isinstance(last_error, httpx.HTTPStatusError):
            raise NIMClientError(
                code="nim_http_error",
                message=f"NIM stream failed after retries with HTTP {last_error.response.status_code}.",
            ) from last_error
        raise NIMClientError(code="nim_unavailable", message="NIM stream is unavailable.") from last_error

    async def multi_model_query(self, messages: list, model_keys: list,
                                 temperature: float = 0.7) -> dict:
        """Query multiple models in parallel and return all responses."""
        coroutines = [
            self.chat_completion(messages, model_key=key, temperature=temperature)
            for key in model_keys
        ]
        raw_results = await asyncio.gather(*coroutines, return_exceptions=True)
        results = {}
        for key, value in zip(model_keys, raw_results):
            if isinstance(value, Exception):
                results[key] = {"error": str(value)}
            else:
                results[key] = value
        return results


# Singleton instance
nim_client = NIMClient()
