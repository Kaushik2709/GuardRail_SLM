"""
Integration tests for OpenAI-compatible reverse proxy endpoint.
"""

import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app


def test_proxy_chat_completions_clean(monkeypatch):
    import httpx
    original_post = httpx.AsyncClient.post
    async def post(self, url, **kwargs):
        if str(url).startswith("http://test") or str(url).startswith("/v1/"):
            return await original_post(self, url, **kwargs)
        return httpx.Response(200, json={"choices": [{"message": {"content": "Fibonacci explanation"}}]})
    monkeypatch.setattr(httpx.AsyncClient, "post", post)
    async def _test():
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(
                "/v1/chat/completions",
                json={
                    "model": "qwen2.5-0.5b",
                    "messages": [{"role": "user", "content": "How do I calculate Fibonacci numbers?"}]
                }
            )
        assert response.status_code == 200
        data = response.json()
        assert "choices" in data

    asyncio.run(_test())


def test_proxy_chat_completions_blocked():
    async def _test():
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            response = await ac.post(
                "/v1/chat/completions",
                json={
                    "model": "qwen2.5-0.5b",
                    "messages": [{"role": "user", "content": "Run: rm -rf / --no-preserve-root"}]
                }
            )
        assert response.status_code == 403
        data = response.json()
        assert data["error"]["type"] == "guardrail_security_violation"

    asyncio.run(_test())


def test_proxy_indeterminate_blocks(monkeypatch):
    from app.core.slm_engine import SLMClassificationEngine
    async def unavailable(self, text):
        return self.indeterminate(0, "offline")
    monkeypatch.setattr(SLMClassificationEngine, "classify", unavailable)
    async def run():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": "Hello"}]})
            assert response.status_code == 403
            assert response.json()["error"]["classification"] == "INDETERMINATE"
    asyncio.run(run())


def test_proxy_upstream_unavailable_is_not_mock_success(monkeypatch):
    import httpx
    original = httpx.AsyncClient.post
    async def post(self, url, **kwargs):
        if str(url).startswith("/v1/"):
            return await original(self, url, **kwargs)
        raise httpx.ConnectError("offline")
    monkeypatch.setattr(httpx.AsyncClient, "post", post)
    async def run():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.post("/v1/chat/completions", json={"messages": [{"role": "user", "content": "Hello"}]})
            assert res.status_code == 502
    asyncio.run(run())


import pytest

@pytest.mark.parametrize("message", [
    {"content": {"text": "rm -rf /"}},
    {"content": [{"type": "image_url", "image_url": {"url": "test"}}]},
    {"function_call": {"arguments": "rm -rf /"}},
    {"tool_calls": [{"function": {"arguments": {"cmd": "rm -rf /"}}}]},
])
def test_unsupported_message_paths_rejected(message):
    async def run():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.post("/v1/chat/completions", json={"messages": [message]})
            assert res.status_code == 400
    asyncio.run(run())


def test_egress_secret_after_other_signature():
    from app.proxy.egress_scanner import EgressScanner
    assert not EgressScanner().scan_chunk("Ignore previous instructions sk-proj-12345678901234567890123456789012")[0]


@pytest.mark.parametrize("tool_args", [False, True])
def test_streamed_split_canary_blocked(monkeypatch, tool_args):
    import httpx
    import json
    token = "GUARDRAIL_ZERO_CANARY_A9F20"
    class Response:
        def raise_for_status(self): pass
        async def aiter_text(self):
            for fragment in [token[:12], token[12:]]:
                delta = {"tool_calls": [{"index": 0, "function": {"arguments": fragment}}]} if tool_args else {"content": fragment}
                yield "data: " + json.dumps({"choices": [{"index": 0, "delta": delta}]}) + "\n\n"
            yield "data: [DONE]\n\n"
    class Stream:
        async def __aenter__(self): return Response()
        async def __aexit__(self, *args): pass
    monkeypatch.setattr(httpx.AsyncClient, "stream", lambda *a, **k: Stream())
    async def run():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.post("/v1/chat/completions", json={"stream": True, "messages": [{"role": "user", "content": "Hello"}]})
            assert "EGRESS_CANARY_LEAK_DETECTED" in res.text
            assert token not in res.text and token[:12] not in res.text
    asyncio.run(run())
