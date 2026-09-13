"""
Exposed Security MCP Tools.
Callable by autonomous agent planners (Claude Desktop, LangGraph, CrewAI, Cursor, Goose)
to inspect memory, verify tool calls, and redact secrets with sub-15ms latency.
"""

from __future__ import annotations

import json
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.core.cascade import SecurityCascadeEngine
from app.core.heuristics import FastHeuristicsEngine

# Global singleton engines for sub-millisecond reuse
cascade = SecurityCascadeEngine()
heuristics = FastHeuristicsEngine()

# Simple high-throughput LRU cache for prompt inspection (avoids repeat SLM inference)
_PROMPT_CACHE_MAX_SIZE = 512
_prompt_cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()


def _get_cached_prompt_result(text: str) -> Optional[Dict[str, Any]]:
    if len(text) > 2048:
        return None
    res = _prompt_cache.get(text)
    if res is not None:
        _prompt_cache.move_to_end(text)
        cached_copy = dict(res)
        cached_copy["inspection_tier"] = "MEMORY_CACHE"
        cached_copy["latency_ms"] = 0.05
        return cached_copy
    return None


def _set_cached_prompt_result(text: str, result: Dict[str, Any]) -> None:
    if len(text) > 2048:
        return
    if len(_prompt_cache) >= _PROMPT_CACHE_MAX_SIZE:
        _prompt_cache.popitem(last=False)
    _prompt_cache[text] = result


def _flatten_arguments(arguments: Any) -> str:
    """Flattens any nested dictionary or list of tool arguments into a searchable string."""
    if isinstance(arguments, (dict, list)):
        try:
            return json.dumps(arguments, ensure_ascii=False)
        except Exception:
            return str(arguments)
    return str(arguments)


# ==========================================
# Pydantic Schemas for MCP Tool Contracts
# ==========================================

class PromptInspectionResult(BaseModel):
    is_safe: bool = Field(..., description="Whether the prompt or context is safe to process.")
    verdict: str = Field(..., description="'SAFE' or 'BLOCKED'")
    threat_type: Optional[str] = Field(None, description="Classification of the detected threat, if any.")
    confidence: float = Field(..., description="Confidence score between 0.0 and 1.0.")
    inspection_tier: str = Field(..., description="Inspection tier that made the determination.")
    latency_ms: float = Field(..., description="Wall-clock latency in milliseconds.")
    details: Dict[str, Any] = Field(default_factory=dict, description="Metadata and rule-match details.")


class ToolVerificationResult(BaseModel):
    approved: bool = Field(..., description="True if safe to execute downstream; False if blocked.")
    tool_name: str = Field(..., description="Target tool name.")
    threat_type: Optional[str] = Field(None, description="Type of threat detected, if blocked.")
    reason: Optional[str] = Field(None, description="Diagnostic justification for approval or blocking.")
    inspection_tier: str = Field(..., description="Evaluation engine tier.")
    latency_ms: float = Field(..., description="Evaluation latency in milliseconds.")


class PIIRedactionResult(BaseModel):
    redacted_text: str = Field(..., description="Sanitized text with confidential tokens masked.")
    secrets_found_count: int = Field(..., description="Total count of confidential tokens masked.")
    secret_types: List[str] = Field(default_factory=list, description="Unique secret categories identified.")


# ==========================================
# Core Tool Functions
# ==========================================

async def guardrail_inspect_prompt(text: str) -> Dict[str, Any]:
    """
    Sub-15ms firewall inspection for untrusted prompts, web scrapers, and RAG contexts
    before an autonomous agent inserts them into its working memory.
    """
    # Fast path for empty / whitespace input
    if not text or not text.strip():
        return {
            "is_safe": True,
            "verdict": "SAFE",
            "threat_type": None,
            "confidence": 1.0,
            "inspection_tier": "FAST_BYPASS",
            "latency_ms": 0.01,
            "details": {"reason": "empty_input"}
        }

    # Micro-cache lookup
    cached = _get_cached_prompt_result(text)
    if cached is not None:
        return cached

    result = await cascade.inspect_text(text)
    output: Dict[str, Any] = {
        "is_safe": result.is_safe,
        "verdict": "SAFE" if result.is_safe else "BLOCKED",
        "threat_type": result.threat_type,
        "confidence": result.confidence,
        "inspection_tier": result.tier,
        "latency_ms": round(result.latency_ms, 2),
        "details": result.details
    }

    if result.is_safe:
        _set_cached_prompt_result(text, output)

    return output


async def guardrail_verify_tool_call(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pre-flight validation for high-risk tools (filesystem writes, shell executions, SQL statements, API requests).
    Delegates inspection directly to the SecurityCascadeEngine (Tier-0 heuristics -> Tier-1 SLM).
    """
    t0 = time.perf_counter()
    serialized_args = _flatten_arguments(arguments)
    combined = f"Tool: {tool_name}\nArguments: {serialized_args}"

    # Multi-tier cascade inspection (Tier-0 deterministic heuristics -> Tier-1 SLM)
    result = await cascade.inspect_text(combined)
    total_latency = (time.perf_counter() - t0) * 1000

    return {
        "approved": result.is_safe,
        "tool_name": tool_name,
        "threat_type": result.threat_type,
        "reason": "Verified safe by GuardRail-Zero cascade" if result.is_safe else f"Flagged by {result.tier}: {result.threat_type}",
        "inspection_tier": result.tier,
        "latency_ms": round(total_latency, 2)
    }


def guardrail_redact_pii(text: str) -> Dict[str, Any]:
    """
    Identifies and masks API keys, secrets, authorization tokens, and credentials from text.
    """
    if not text:
        return {
            "redacted_text": "",
            "secrets_found_count": 0,
            "secret_types": []
        }

    redacted = text
    matches_found: List[str] = []

    for name, pattern in heuristics.PATTERNS.items():
        if "KEY" in name or "JWT" in name or "PAT" in name or "CRED" in name:
            for match in pattern.finditer(text):
                token = match.group(0)
                masked = token[:4] + "*" * (len(token) - 8) + token[-4:] if len(token) > 8 else "[REDACTED]"
                redacted = redacted.replace(token, masked)
                matches_found.append(name)

    return {
        "redacted_text": redacted,
        "secrets_found_count": len(matches_found),
        "secret_types": list(set(matches_found))
    }


# ==========================================
# FastMCP Server Registration Helper
# ==========================================

def register_security_tools(mcp: Any) -> None:
    """
    Registers the core security tools onto a FastMCP server instance.
    Generates standard MCP input schemas and documentation.
    """

    @mcp.tool(
        name="guardrail_inspect_prompt",
        description="Sub-15ms firewall inspection for untrusted prompts and RAG contexts before working memory insertion."
    )
    async def _inspect_prompt(text: str) -> Dict[str, Any]:
        return await guardrail_inspect_prompt(text)

    @mcp.tool(
        name="guardrail_verify_tool_call",
        description="Pre-flight validation of tool parameters to block SQL injection, shell commands, path traversal, and SSRF."
    )
    async def _verify_tool_call(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await guardrail_verify_tool_call(tool_name, arguments)

    @mcp.tool(
        name="guardrail_redact_pii",
        description="Redacts sensitive credentials, API keys, JWT tokens, and passwords from text."
    )
    def _redact_pii(text: str) -> Dict[str, Any]:
        return guardrail_redact_pii(text)
