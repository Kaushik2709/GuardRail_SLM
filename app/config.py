"""
Configuration settings for GuardRail-Zero Gateway & Firewall.
Uses Pydantic BaseSettings for dynamic environment variable management.
"""

from typing import List, Optional, Literal
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GUARDRAIL_", case_sensitive=False)

    APP_NAME: str = "GuardRail-Zero"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    
    # Server Gateway settings
    GATEWAY_HOST: str = "0.0.0.0"
    GATEWAY_PORT: int = 8000
    
    # Upstream Target LLM (where clean requests are forwarded)
    UPSTREAM_LLM_URL: str = "http://localhost:8003/v1/chat/completions"
    UPSTREAM_API_KEY: Optional[str] = None
    
    # Tier-1 SLM Classification Server (vLLM or local inference)
    SLM_SERVING_URL: str = "http://localhost:8001/v1/completions"
    SLM_MODEL_NAME: str = "Qwen/Qwen2.5-0.5B-Instruct"
    SLM_TIMEOUT_SECONDS: float = 0.5  # 500ms max circuit-breaker
    
    # Indeterminate classifications remain distinct from enforcement decisions.
    PROXY_FAILURE_POLICY: Literal["allow", "block"] = "block"
    TOOL_FAILURE_POLICY: Literal["allow", "block"] = "block"
    PROMPT_FAILURE_POLICY: Literal["allow", "block"] = "block"

    # Tier-0 Heuristic Thresholds
    ENTROPY_THRESHOLD: float = 4.85
    ENABLE_TIER0_HEURISTICS: bool = True
    ENABLE_TIER1_SLM: bool = True
    
    # Canary token monitoring
    CANARY_TOKENS: List[str] = [
        "GUARDRAIL_ZERO_CANARY_A9F20",
        "CANARY_SECRET_PREFIX_77B12"
    ]
    
    # Audit logging
    AUDIT_LOG_FILE: str = "logs/security_audit.jsonl"


settings = Settings()
