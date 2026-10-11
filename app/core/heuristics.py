"""
Tier-0: Deterministic Fast Heuristics Engine (< 1.5ms).
Optimized: single-pass combined regex, single-pass canary matching,
and streaming entropy scanning instead of full word-list materialization.

Behavioral note vs. the original:
  The original loop returns the first RULE (in declaration order) that
  matches anywhere in the text. This version returns the LEFTMOST match
  in the text (rule order is only a tiebreaker for same-position matches).
  This changes which threat_type is reported when an input contains more
  than one distinct signature. Confirm this is acceptable before swapping
  it in.
"""

import math
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Classification(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    INDETERMINATE = "INDETERMINATE"


@dataclass(slots=True)  # requires Python 3.10+; drop slots=True on older versions
class InspectionResult:
    is_safe: bool
    threat_type: Optional[str] = None
    confidence: float = 1.0
    tier: str = "TIER_0"
    latency_ms: float = 0.0
    details: dict = field(default_factory=dict)
    classification: Optional[Classification] = None

    def __post_init__(self):
        if self.classification is None:
            self.classification = Classification.ALLOW if self.is_safe else Classification.BLOCK
        # Compatibility boolean never grants permission for an indeterminate result.
        self.is_safe = self.classification == Classification.ALLOW

    def permits(self, context: str = "proxy") -> bool:
        from app.config import settings
        if self.classification == Classification.INDETERMINATE:
            policy = {"proxy": settings.PROXY_FAILURE_POLICY,
                      "tool": settings.TOOL_FAILURE_POLICY,
                      "prompt": settings.PROMPT_FAILURE_POLICY}[context]
            return policy == "allow"
        return self.classification == Classification.ALLOW


class FastHeuristicsEngine:
    """
    Ultra-low latency Tier-0 inspection engine designed to execute in < 1.5ms.
    """

    # Pattern bodies only (no top-level flags). Patterns that need
    # case-insensitivity use a *scoped* inline flag (?i:...) so they can
    # all live inside one compiled alternation regardless of flag mix.
    _RAW_PATTERNS = {
        "AWS_KEY": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "OPENAI_KEY": r"sk-(?:proj-)?[A-Za-z0-9_-]{32,}",
        "GITHUB_PAT": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "GENERIC_JWT": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*",
        "PATH_TRAVERSAL": (
            r"(?i:(?:\.\.[/\\]|%2e%2e[/\\]|\.\.%2f|\.\.%5c|/etc/(?:passwd|shadow|hosts)|~/(?:\.ssh|\.bashrc|\.aws)))"
        ),
        "DANGEROUS_SHELL": (
            r"(?i:(?:rm\s+-[rRf]+\s+/|curl\s+.*?\|\s*(?:bash|sh)|wget\s+.*?\|\s*(?:bash|sh)|"
            r"chmod\s+777\s+/|:\(\)\{\s*:\|:&\s*\};:|powershell\s+-(?:enc|encodedcommand)|"
            r";\s*(?:rm\s+-[rRf]+|curl|wget|bash|sh|powershell|chmod|kill|dd)))"
        ),
        "SQL_DESTRUCTIVE": (
            r"(?i:\b(?:DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE(?:\s+TABLE)?|"
            r"DELETE\s+FROM\s+\w+|ALTER\s+TABLE\s+.*?DROP)\b)"
        ),
        "SSRF_METADATA": (
            r"(?i:(?:https?://)?(?:169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost|0\.0\.0\.0)(?::\d+)?(?:/|$))"
        ),
        "SYSTEM_OVERRIDE": (
            r"(?i:(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
            r"system\s+override\s*:|you\s+are\s+now\s+in\s+developer\s+mode|"
            r"jailbreak\s+activated))"
        ),
    }

    # Precomputed once, at class-definition time, instead of doing
    # `"KEY" in threat_name` string containment checks on every hit.
    _THREAT_CATEGORY = {
        "AWS_KEY": "PII_LEAK",
        "OPENAI_KEY": "PII_LEAK",
        "GITHUB_PAT": "PII_LEAK",
        "GENERIC_JWT": "PII_LEAK",
        "PATH_TRAVERSAL": "PATH_TRAVERSAL",
        "DANGEROUS_SHELL": "MALICIOUS_TOOL_CALL",
        "SQL_DESTRUCTIVE": "MALICIOUS_TOOL_CALL",
        "SSRF_METADATA": "SSRF_CLOUD_METADATA",
        "SYSTEM_OVERRIDE": "INJECTION_DIRECT",
    }

    # One compiled alternation instead of 7 separate compiled patterns.
    # A single .search() lets the engine make one pass over the text
    # instead of the Python loop calling .search() seven times.
    COMBINED_PATTERN = re.compile(
        "|".join(f"(?P<{name}>{body})" for name, body in _RAW_PATTERNS.items())
    )

    # Individual compiled patterns for tools that need per-pattern iteration (e.g. MCP PII redaction)
    PATTERNS = {
        name: re.compile(body) for name, body in _RAW_PATTERNS.items()
    }

    # Candidates for the entropy check: any run of 40+ non-whitespace
    # characters, found directly via regex instead of building a full
    # list of every word in the input via str.split().
    _LONG_TOKEN_RE = re.compile(r"\S{40,}")

    def __init__(self, entropy_threshold: float = 4.85, canary_tokens: Optional[List[str]] = None):
        self.entropy_threshold = entropy_threshold
        self.canary_tokens = canary_tokens or []
        # Single compiled alternation for canaries instead of a Python loop
        # doing `token in text` per token — O(n) regardless of list size.
        self._canary_pattern = (
            re.compile("|".join(re.escape(t) for t in self.canary_tokens))
            if self.canary_tokens
            else None
        )

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Computes Shannon entropy of character distribution."""
        if not text:
            return 0.0
        length = len(text)
        entropy = 0.0
        for count in Counter(text).values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def inspect(self, text: str) -> InspectionResult:
        """
        Runs Tier-0 deterministic heuristic checks on input text.
        Execution target: < 1.5ms.
        """
        t0 = time.perf_counter()

        if not text or not text.strip():
            return InspectionResult(is_safe=True, latency_ms=(time.perf_counter() - t0) * 1000)

        # 1. Canary token check — one regex pass instead of N substring scans.
        if self._canary_pattern is not None:
            canary_match = self._canary_pattern.search(text)
            if canary_match:
                return InspectionResult(
                    is_safe=False,
                    threat_type="CANARY_LEAK",
                    confidence=1.0,
                    latency_ms=(time.perf_counter() - t0) * 1000,
                    details={"canary_detected": True},
                )

        # 2. Combined regex signature scan — one pass instead of seven.
        match = self.COMBINED_PATTERN.search(text)
        if match:
            name = match.lastgroup
            return InspectionResult(
                is_safe=False,
                threat_type=self._THREAT_CATEGORY[name],
                confidence=0.99,
                latency_ms=(time.perf_counter() - t0) * 1000,
                details={"rule": name, "snippet": "[REDACTED]" if self._THREAT_CATEGORY[name] == "PII_LEAK" else match.group(0)[:60]},
            )

        # 3. High-entropy obfuscation check (Base64 / encrypted strings >= 40 chars).
        # Skip entirely if the input can't contain a long-enough token,
        # and stream candidates via regex instead of materializing every
        # word in the text with str.split().
        if len(text) >= 40:
            for m in self._LONG_TOKEN_RE.finditer(text):
                word = m.group(0)
                if "http://" in word or "https://" in word:
                    continue
                entropy = self.calculate_shannon_entropy(word)
                if entropy > self.entropy_threshold:
                    return InspectionResult(
                        is_safe=False,
                        threat_type="OBFUSCATED_PAYLOAD",
                        confidence=0.95,
                        latency_ms=(time.perf_counter() - t0) * 1000,
                        details={"entropy": round(entropy, 3), "word_sample": word[:30]},
                    )

        return InspectionResult(is_safe=True, latency_ms=(time.perf_counter() - t0) * 1000)