import asyncio

import pytest

from core import nvidia_nim_provider as nim_mod
from core.nvidia_nim_provider import NVIDIANIMProvider


def test_provider_init_reports_unavailable_when_litellm_missing(monkeypatch):
    monkeypatch.setattr(nim_mod, "acompletion", None)
    monkeypatch.setattr(nim_mod, "aembedding", None)
    provider = NVIDIANIMProvider()
    assert provider.available is False
    assert "litellm is not installed" in provider.unavailable_reason


def test_provider_init_raises_if_fallback_disabled_and_litellm_missing(monkeypatch):
    monkeypatch.setattr(nim_mod, "acompletion", None)
    monkeypatch.setattr(nim_mod, "aembedding", None)
    monkeypatch.setenv("ENABLE_OLLAMA_FALLBACK", "false")
    with pytest.raises(RuntimeError, match="Fallback is disabled"):
        NVIDIANIMProvider()


def test_provider_methods_raise_cleanly_when_unavailable(monkeypatch):
    async def _run():
        monkeypatch.setattr(nim_mod, "acompletion", None)
        monkeypatch.setattr(nim_mod, "aembedding", None)
        provider = NVIDIANIMProvider()
        with pytest.raises(RuntimeError, match="litellm is not installed"):
            await provider.get_embedding("x")

    asyncio.run(_run())
