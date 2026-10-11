"""
Multi-Tier Cascade Coordinator.
Orchestrates Tier-0 Fast Heuristics and Tier-1 SLM Classification.
Applies circuit-breaker optimization: skips SLM inference if Tier-0 flags a violation.
"""

import time
from typing import List, Union
from app.core.heuristics import FastHeuristicsEngine, InspectionResult
from app.core.slm_engine import SLMClassificationEngine
from app.config import settings


class SecurityCascadeEngine:
    """
    Coordinates multi-tier security inspection pipeline:
    Tier-0 heuristics -> Tier-1 generative labels -> ALLOW / BLOCK / INDETERMINATE.
    """

    def __init__(
        self,
        heuristics_engine: FastHeuristicsEngine = None,
        slm_engine: SLMClassificationEngine = None
    ):
        self.heuristics = heuristics_engine or FastHeuristicsEngine(
            entropy_threshold=settings.ENTROPY_THRESHOLD,
            canary_tokens=settings.CANARY_TOKENS
        )
        self.slm = slm_engine or SLMClassificationEngine()

    async def inspect_text(self, text: str) -> InspectionResult:
        """
        Inspects a single text string through the cascade pipeline.
        """
        total_t0 = time.perf_counter()

        # Tier-0 Deterministic Heuristics
        if settings.ENABLE_TIER0_HEURISTICS:
            res0 = self.heuristics.inspect(text)
            if not res0.is_safe:
                res0.latency_ms = (time.perf_counter() - total_t0) * 1000
                return res0

        # Tier-1 SLM Engine
        if settings.ENABLE_TIER1_SLM:
            try:
                res1 = await self.slm.classify(text)
                if not isinstance(res1, InspectionResult):
                    return self.slm.indeterminate(total_t0, "invalid_classifier_result")
            except Exception as exc:
                return SLMClassificationEngine.indeterminate(total_t0, type(exc).__name__)
            res1.latency_ms = (time.perf_counter() - total_t0) * 1000
            return res1

        total_latency = (time.perf_counter() - total_t0) * 1000
        return InspectionResult(is_safe=True, latency_ms=total_latency)

    async def inspect_messages(self, messages: List[dict]) -> InspectionResult:
        """
        Inspects a list of OpenAI-style chat completion messages.
        Extracts content from user and system roles, plus tool calls.
        """
        total_t0 = time.perf_counter()
        
        extracted_parts = []
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                extracted_parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and "text" in part:
                        extracted_parts.append(part["text"])
            
            # Check tool calls
            tool_calls = msg.get("tool_calls", [])
            for tc in tool_calls:
                func = tc.get("function", {})
                args = func.get("arguments", "")
                name = func.get("name", "")
                extracted_parts.append(f"Tool Call: {name}(arguments={args})")

        combined_text = "\n".join(extracted_parts)
        result = await self.inspect_text(combined_text)
        result.latency_ms = (time.perf_counter() - total_t0) * 1000
        return result
