"""NVIDIA NIM provider adapter (v2).

v2 can run without NIM (tool-only runs). When configured, this provides a thin
async client compatible with the run/task model.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import AsyncGenerator

import httpx

from nexus_v2.config import get_settings


class NIMError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int = 502):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class NIMProvider:
    def __init__(self):
        settings = get_settings()
        self.api_key = settings.nvidia_api_key
        self.base_url = settings.nvidia_base_url
        self._client: httpx.AsyncClient | None = None
        self.timeout = httpx.Timeout(120.0, connect=15.0)

    async def start(self) -> None:
        if self._client is not None:
            return
        self._client = httpx.AsyncClient(timeout=self.timeout)

    async def stop(self) -> None:
        if self._client is None:
            return
        await self._client.aclose()
        self._client = None

    async def _client_ready(self) -> httpx.AsyncClient:
        if self._client is None:
            await self.start()
        assert self._client is not None
        return self._client

    def _headers(self, operation: str) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "X-Request-ID": str(uuid.uuid4()),
            "X-Nexus-Operation": operation,
        }

    async def chat_completion(
        self,
        *,
        messages: list[dict],
        model: str,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        metadata: dict | None = None,
    ) -> str:
        if not (self.api_key or "").strip():
            raise NIMError("nim_missing_api_key", "NVIDIA_API_KEY is not configured.", 503)
        client = await self._client_ready()
        payload = {"model": model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens}
        if metadata:
            payload["metadata"] = metadata
        try:
            resp = await client.post(f"{self.base_url}/chat/completions", headers=self._headers("chat_completion"), json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise NIMError("nim_http_error", str(exc), 502) from exc
        data = resp.json()
        choices = data.get("choices") or []
        if not choices:
            return ""
        msg = choices[0].get("message") or {}
        return str(msg.get("content") or "")

    async def chat_completion_stream(
        self,
        *,
        messages: list[dict],
        model: str,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        metadata: dict | None = None,
    ) -> AsyncGenerator[str, None]:
        if not (self.api_key or "").strip():
            raise NIMError("nim_missing_api_key", "NVIDIA_API_KEY is not configured.", 503)
        client = await self._client_ready()
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }
        if metadata:
            payload["metadata"] = metadata
        async with client.stream(
            "POST",
            f"{self.base_url}/chat/completions",
            headers=self._headers("chat_stream"),
            json=payload,
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                data_str = line[6:]
                if data_str.strip() == "[DONE]":
                    return
                try:
                    data = json.loads(data_str)
                except Exception:
                    continue
                delta = (data.get("choices") or [{}])[0].get("delta") or {}
                tok = str(delta.get("content") or "")
                if tok:
                    yield tok


nim_provider = NIMProvider()

