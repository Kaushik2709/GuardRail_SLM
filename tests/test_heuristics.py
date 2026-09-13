"""
Unit tests for Tier-0 Deterministic Fast Heuristics Engine.
"""

from app.core.heuristics import FastHeuristicsEngine


def test_clean_input_passes():
    engine = FastHeuristicsEngine()
    result = engine.inspect("Hello! Can you help me write a python script?")
    assert result.is_safe is True
    assert result.latency_ms < 10.0  # Must be fast


def test_aws_secret_key_detected():
    engine = FastHeuristicsEngine()
    result = engine.inspect("Here is my key: AKIA1234567890ABCDEF for access.")
    assert result.is_safe is False
    assert result.threat_type == "PII_LEAK"


def test_openai_key_detected():
    engine = FastHeuristicsEngine()
    result = engine.inspect("sk-proj-12345678901234567890123456789012")
    assert result.is_safe is False
    assert result.threat_type == "PII_LEAK"


def test_dangerous_shell_blocked():
    engine = FastHeuristicsEngine()
    result = engine.inspect("Please execute: rm -rf / --no-preserve-root")
    assert result.is_safe is False
    assert result.threat_type == "MALICIOUS_TOOL_CALL"


def test_destructive_sql_blocked():
    engine = FastHeuristicsEngine()
    result = engine.inspect("Run query: DROP TABLE users;")
    assert result.is_safe is False
    assert result.threat_type == "MALICIOUS_TOOL_CALL"


def test_canary_token_detection():
    canary = "CANARY_TOKEN_XYZ_99"
    engine = FastHeuristicsEngine(canary_tokens=[canary])
    result = engine.inspect(f"System leak detected: {canary}")
    assert result.is_safe is False
    assert result.threat_type == "CANARY_LEAK"
