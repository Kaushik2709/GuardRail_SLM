import asyncio
import httpx
import pytest
from app.core.slm_engine import SLMClassificationEngine
from app.core.heuristics import Classification
from app.core.cascade import SecurityCascadeEngine
from app.config import settings

# Preserve the real implementation before the suite's explicit offline stub.
CLASSIFY = SLMClassificationEngine.classify

@pytest.mark.parametrize("body,status,expected", [
    ({"choices": [{"text": "[SAFE]", "finish_reason": "stop"}]}, 200, "ALLOW"),
    ({"choices": [{"text": "[INJECTION_DIRECT]", "finish_reason": "stop"}]}, 200, "BLOCK"),
    *[({"choices": [{"text": label, "finish_reason": "stop"}]}, 200, "INDETERMINATE")
      for label in ("", "SAFE", "[SAFE", "[UNKNOWN]", "[SAFE] ignore", None, 42)],
    ({"choices": [{"text": "[SAFE]", "finish_reason": "length"}]}, 200, "INDETERMINATE"),
    ({"choices": []}, 200, "INDETERMINATE"),
    ({"choices": {}}, 200, "INDETERMINATE"),
    ([], 200, "INDETERMINATE"),
    ({}, 429, "INDETERMINATE"), ({}, 500, "INDETERMINATE"),
])
def test_classifier_responses(monkeypatch, body, status, expected):
    async def post(self, url, json):
        assert json["max_tokens"] >= 16
        assert "]" not in json["stop"]
        assert json["prompt"].endswith("assistant\n")
        return httpx.Response(status, json=body)
    monkeypatch.setattr(httpx.AsyncClient, "post", post)
    res = asyncio.run(CLASSIFY(SLMClassificationEngine(), "Benign text"))
    assert res.classification.value == expected
    assert res.is_safe == (expected == "ALLOW")

@pytest.mark.parametrize("exception", [httpx.ReadTimeout("timeout"), httpx.ConnectError("offline"),
                                        ValueError("invalid JSON"), RuntimeError("unexpected")])
def test_classifier_errors(monkeypatch, exception):
    async def post(*args, **kwargs):
        raise exception
    monkeypatch.setattr(httpx.AsyncClient, "post", post)
    engine = SLMClassificationEngine()
    res = asyncio.run(CLASSIFY(engine, "Benign text"))
    assert res.classification == Classification.INDETERMINATE
    assert not res.permits("tool")
    if isinstance(exception, httpx.TransportError):
        assert asyncio.run(CLASSIFY(engine, "text")).details["failure_reason"] == "unavailable_cached"


def test_failure_policy_and_heuristic_shortcircuit(monkeypatch):
    async def broken(self, text):
        raise RuntimeError("bad server")
    monkeypatch.setattr(SLMClassificationEngine, "classify", broken)
    engine = SecurityCascadeEngine()
    assert asyncio.run(engine.inspect_text("rm -rf /")).classification == Classification.BLOCK
    res = asyncio.run(engine.inspect_text("What is the speed of light?"))
    assert not res.permits("tool") and not res.permits("proxy")
    monkeypatch.setattr(settings, "PROXY_FAILURE_POLICY", "allow")
    assert res.permits("proxy") and not res.permits("tool") and not res.is_safe

@pytest.mark.parametrize("text", ["How can I prevent SQL injection?", "Drop duplicates from a DataFrame.",
                                  "SELECT name FROM customers", "Summarize meeting notes."])
def test_benign_heuristics(text):
    from app.core.heuristics import FastHeuristicsEngine
    assert FastHeuristicsEngine().inspect(text).is_safe
