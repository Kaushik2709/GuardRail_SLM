"""
Unit tests for Tier-1 SLM Classification Engine & Cascade.
"""

import asyncio
from app.core.slm_engine import SLMClassificationEngine
from app.core.cascade import SecurityCascadeEngine


def test_slm_offline_fallback():
    async def _test():
        engine = SLMClassificationEngine()
        # Testing with server offline should invoke graceful fallback
        res = await engine.classify("What is the speed of light?")
        assert res.is_safe is True
        assert res.tier in ["TIER_1_SLM", "TIER_1_FALLBACK"]

    asyncio.run(_test())


def test_cascade_block_tier0_shortcircuit():
    async def _test():
        cascade = SecurityCascadeEngine()
        # Tier-0 threat should be blocked instantly
        res = await cascade.inspect_text("rm -rf /")
        assert res.is_safe is False
        assert res.tier == "TIER_0"
        assert res.latency_ms < 10.0  # Should be fast

    asyncio.run(_test())
