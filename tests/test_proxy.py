"""
Integration tests for OpenAI-compatible reverse proxy endpoint.
"""

import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app


def test_proxy_chat_completions_clean():
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
