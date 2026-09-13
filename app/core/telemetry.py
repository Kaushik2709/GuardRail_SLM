"""
Telemetry, metrics, and tamper-evident audit logging for GuardRail-Zero.
Outputs structured JSON records for security event auditing.
"""

import json
import os
import time
from datetime import datetime, timezone
from typing import Optional
from app.config import settings
from app.core.heuristics import InspectionResult


class SecurityAuditLogger:
    """
    Append-only structured JSON audit log for threat analysis and monitoring.
    """

    def __init__(self, log_file: Optional[str] = None):
        self.log_file = log_file or settings.AUDIT_LOG_FILE
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

    def log_event(
        self,
        endpoint: str,
        client_ip: Optional[str],
        inspection: InspectionResult,
        extra_metadata: Optional[dict] = None
    ):
        """Records an audit event asynchronously / non-blocking."""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "endpoint": endpoint,
            "client_ip": client_ip or "unknown",
            "verdict": "SAFE" if inspection.is_safe else "BLOCKED",
            "threat_type": inspection.threat_type,
            "confidence": inspection.confidence,
            "inspection_tier": inspection.tier,
            "latency_ms": round(inspection.latency_ms, 2),
            "details": inspection.details,
            "metadata": extra_metadata or {}
        }

        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            # Fallback stdout log
            print(f"[AUDIT_LOG_ERROR] {e} | {event}")


audit_logger = SecurityAuditLogger()
