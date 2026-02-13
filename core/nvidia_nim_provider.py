import asyncio
import hashlib
import json
import os
from typing import Any, Dict, List, Optional

from litellm import acompletion, aembedding
from loguru import logger


class NVIDIANIMProvider:
    """NVIDIA NIM provider with retries, lightweight cache, and Ollama fallback."""

    def __init__(self) -> None:
        self.api_key = os.getenv("NIM_API_KEY")
        self.base_url = os.getenv("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")
        self.enable_fallback = os.getenv("ENABLE_OLLAMA_FALLBACK", "true").lower() == "true"
        self.models: Dict[str, Dict[str, Any]] = {
            "reasoning": {"model": "nvidia/nemotron-4-340b-instruct", "max_tokens": 4096, "temperature": 0.2},
            "fast": {"model": "meta/llama-3.1-8b-instruct", "max_tokens": 2048, "temperature": 0.3},
            "code": {"model": "mistralai/codestral-22b-instruct-v0.1", "max_tokens": 8192, "temperature": 0.1},
            "embedding": {"model": "nvidia/nv-embedqa-e5-v5", "dimensions": 1536},
        }
        self.call_count = 0
        self.total_tokens = 0
        self.fallback_count = 0
        self._cache: Dict[str, Dict[str, Any]] = {}
        logger.info("NVIDIA NIM provider ready")

    async def call_async(
        self,
        prompt: str,
        model_type: str = "reasoning",
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        system_prompt: Optional[str] = None,
        response_format: str = "text",
    ) -> Dict[str, Any]:
        model_cfg = self.models.get(model_type, self.models["reasoning"])
        cache_key = self._make_cache_key(prompt, model_type, temperature, max_tokens, system_prompt, response_format)
        if cache_key in self._cache:
            return self._cache[cache_key]

        messages = [{"role": "user", "content": prompt}]
        if system_prompt:
            messages.insert(0, {"role": "system", "content": system_prompt})

        for attempt in range(3):
            try:
                resp = await acompletion(
                    model=f"nvidia_nim/{model_cfg['model']}",
                    messages=messages,
                    api_base=self.base_url,
                    api_key=self.api_key,
                    temperature=temperature if temperature is not None else model_cfg.get("temperature", 0.2),
                    max_tokens=max_tokens if max_tokens is not None else model_cfg.get("max_tokens", 1024),
                    response_format={"type": "json_object"} if response_format == "json" else None,
                    timeout=300,
                )
                usage = getattr(resp, "usage", None)
                p = getattr(usage, "prompt_tokens", 0) if usage else 0
                c = getattr(usage, "completion_tokens", 0) if usage else 0
                t = getattr(usage, "total_tokens", p + c) if usage else p + c
                self.call_count += 1
                self.total_tokens += t
                result = {
                    "content": resp.choices[0].message.content,
                    "model": model_cfg["model"],
                    "usage": {"prompt_tokens": p, "completion_tokens": c, "total_tokens": t},
                    "finish_reason": resp.choices[0].finish_reason,
                    "success": True,
                    "fallback_used": False,
                }
                self._cache[cache_key] = result
                return result
            except Exception as exc:
                logger.warning(f"NIM call failed on attempt {attempt + 1}: {exc}")
                await asyncio.sleep(2**attempt)

        if self.enable_fallback:
            return await self._fallback_ollama(prompt, system_prompt, temperature, max_tokens)
        raise RuntimeError("NIM call failed and fallback disabled")

    def call_sync(self, prompt: str, **kwargs: Any) -> Dict[str, Any]:
        return asyncio.run(self.call_async(prompt, **kwargs))

    async def _fallback_ollama(
        self,
        prompt: str,
        system_prompt: Optional[str],
        temperature: Optional[float],
        max_tokens: Optional[int],
    ) -> Dict[str, Any]:
        self.fallback_count += 1
        messages = [{"role": "user", "content": prompt}]
        if system_prompt:
            messages.insert(0, {"role": "system", "content": system_prompt})
        resp = await acompletion(
            model="ollama/qwen2.5:32b",
            messages=messages,
            api_base="http://localhost:11434",
            temperature=temperature or 0.2,
            max_tokens=max_tokens or 2048,
        )
        return {
            "content": resp.choices[0].message.content,
            "model": "ollama/qwen2.5:32b",
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "finish_reason": resp.choices[0].finish_reason,
            "success": True,
            "fallback_used": True,
        }

    async def get_embedding(self, text: str) -> List[float]:
        resp = await aembedding(
            model=f"nvidia_nim/{self.models['embedding']['model']}",
            input=[text],
            api_base=self.base_url,
            api_key=self.api_key,
        )
        return resp.data[0]["embedding"]

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "total_calls": self.call_count,
            "total_tokens": self.total_tokens,
            "fallback_calls": self.fallback_count,
            "fallback_percentage": (self.fallback_count / self.call_count * 100) if self.call_count else 0,
        }

    @staticmethod
    def _make_cache_key(*parts: Any) -> str:
        return hashlib.md5(json.dumps(parts, default=str).encode()).hexdigest()
