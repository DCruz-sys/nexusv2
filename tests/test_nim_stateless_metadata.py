import unittest
from unittest.mock import AsyncMock, patch

from app.ai.nim_client import nim_client


class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def json(self):
        return self._payload


class NIMStatelessMetadataTests(unittest.IsolatedAsyncioTestCase):
    def test_headers_include_stateless_metadata(self):
        headers = nim_client._get_headers(operation="unit_test")
        self.assertIn("X-Request-ID", headers)
        self.assertIn("X-Correlation-ID", headers)
        self.assertEqual(headers.get("X-Nexus-Operation"), "unit_test")

    async def test_chat_completion_passes_metadata_payload(self):
        fake = _FakeResponse({"choices": [{"message": {"content": "ok"}}]})
        with patch.object(nim_client, "_post_with_retry", new=AsyncMock(return_value=fake)) as mocked:
            result = await nim_client.chat_completion(
                messages=[{"role": "user", "content": "hello"}],
                model_key="llama-3.1-8b",
                metadata={"request_id": "req-1"},
            )
            self.assertEqual(result, "ok")
            self.assertTrue(mocked.await_count == 1)
            call_kwargs = mocked.await_args.kwargs
            self.assertIn("payload", call_kwargs)
            self.assertEqual(call_kwargs["payload"].get("metadata", {}).get("request_id"), "req-1")
