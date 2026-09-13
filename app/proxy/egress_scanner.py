"""
Egress Scanner: Inspects outbound model responses and tool results.
Verifies against system prompt canary leaks and accidental secret exfiltration.
"""

from typing import List, Optional, Tuple
from app.config import settings
from app.core.heuristics import FastHeuristicsEngine


class EgressScanner:
    """
    High-speed egress inspector ensuring model generation does not leak canary tokens or secrets.
    """

    def __init__(self, canary_tokens: Optional[List[str]] = None):
        self.canary_tokens = canary_tokens or settings.CANARY_TOKENS
        self.heuristics = FastHeuristicsEngine(canary_tokens=self.canary_tokens)

    def scan_chunk(self, chunk_text: str) -> Tuple[bool, Optional[str]]:
        """
        Scans an individual streaming chunk or full text.
        Returns (is_safe, sanitized_or_block_reason).
        """
        if not chunk_text:
            return True, None

        # Check canaries
        for token in self.canary_tokens:
            if token in chunk_text:
                return False, "EGRESS_CANARY_LEAK_DETECTED"

        # Check high-confidence secret keys in egress
        res = self.heuristics.inspect(chunk_text)
        if not res.is_safe and res.threat_type == "PII_LEAK":
            return False, "EGRESS_SECRET_LEAK_DETECTED"

        return True, None
