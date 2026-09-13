"""
MCP Interceptor Middleware.
Zero-trust security layer for Model Context Protocol (MCP) tool execution.
Intercepts incoming tool calls, verifies arguments against malicious patterns,
blocks attacks before reaching downstream MCP servers, and sanitizes tool outputs.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional, Set
import mcp.types as mt
from fastmcp.server.middleware.middleware import Middleware, MiddlewareContext, CallNext
from fastmcp.tools.base import ToolResult
from app.mcp.tools import guardrail_verify_tool_call, guardrail_redact_pii

logger = logging.getLogger("guardrail.mcp.interceptor")


class MCPInterceptor(Middleware):
    """
    Zero-trust FastMCP middleware for autonomous agent tool execution.
    - Inspects high-risk tool arguments (shell, filesystem, SQL, network)
    - Blocks path traversal, command injection, and SSRF before execution
    - Sanitizes outgoing tool execution outputs to prevent credential/PII leakage
    """

    EXEMPT_TOOLS: Set[str] = {
        "guardrail_inspect_prompt",
        "guardrail_verify_tool_call",
        "guardrail_redact_pii"
    }

    def __init__(self, sanitize_outputs: bool = True):
        super().__init__()
        self.sanitize_outputs = sanitize_outputs

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """
        FastMCP middleware hook invoked before any tool execution.
        """
        tool_name = context.message.name
        arguments = context.message.arguments or {}

        # Skip self-auditing guardrail tools to prevent recursive inspection
        if tool_name in self.EXEMPT_TOOLS:
            return await call_next(context)

        # 1. Pre-flight parameter verification
        verification = await guardrail_verify_tool_call(tool_name, arguments)

        if not verification.get("approved"):
            threat = verification.get("threat_type", "SECURITY_POLICY_VIOLATION")
            reason = verification.get("reason", "Malicious or unauthorized parameter detected.")
            latency = verification.get("latency_ms", 0.0)

            logger.warning(
                f"[MCP Interceptor] Blocked tool execution: {tool_name} | "
                f"Threat: {threat} | Latency: {latency}ms"
            )

            error_message = (
                f"🛑 [GuardRail-Zero MCP Interceptor] Tool call blocked.\n"
                f"Target Tool: {tool_name}\n"
                f"Threat Detected: {threat}\n"
                f"Reason: {reason}\n"
                f"Inspection Latency: {latency}ms"
            )

            return ToolResult(
                content=error_message,
                is_error=True
            )

        # 2. Execute downstream tool
        result: ToolResult = await call_next(context)

        # 3. Post-execution output sanitization (PII / Secrets redaction)
        if self.sanitize_outputs:
            if result.content:
                sanitized_blocks = []
                for block in result.content:
                    if hasattr(block, "text") and isinstance(block.text, str):
                        redaction = guardrail_redact_pii(block.text)
                        if redaction.get("secrets_found_count", 0) > 0:
                            block.text = redaction.get("redacted_text", block.text)
                    sanitized_blocks.append(block)
                result.content = sanitized_blocks

            if result.structured_content and isinstance(result.structured_content, dict):
                for k, v in list(result.structured_content.items()):
                    if isinstance(v, str):
                        red = guardrail_redact_pii(v)
                        if red.get("secrets_found_count", 0) > 0:
                            result.structured_content[k] = red["redacted_text"]

        return result

    async def intercept_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        downstream_executor: Callable[[str, Dict[str, Any]], Any]
    ) -> Dict[str, Any]:
        """
        Backward-compatible programmatic interceptor for custom agent executors.
        """
        verification = await guardrail_verify_tool_call(tool_name, arguments)

        if not verification.get("approved"):
            return {
                "isError": True,
                "content": [{
                    "type": "text",
                    "text": (
                        f"🛑 [GuardRail-Zero MCP Interceptor] Tool call blocked. "
                        f"Threat detected: {verification.get('threat_type')}. "
                        f"Inspection time: {verification.get('latency_ms', 0)}ms."
                    )
                }],
                "verification": verification
            }

        # Safe to execute downstream tool
        execution_result = await downstream_executor(tool_name, arguments)

        # Sanitize result if it contains text
        if self.sanitize_outputs and isinstance(execution_result, str):
            redaction = guardrail_redact_pii(execution_result)
            if redaction.get("secrets_found_count", 0) > 0:
                execution_result = redaction.get("redacted_text", execution_result)

        return execution_result
