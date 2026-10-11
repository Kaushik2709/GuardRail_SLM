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
from app.mcp.tools import guardrail_verify_tool_call, guardrail_redact_pii, cascade


async def inspect_output(value):
    """Inspect and redact every textual leaf, including nested structured results."""
    if isinstance(value, str):
        text = guardrail_redact_pii(value)["redacted_text"]
        result = await cascade.inspect_text(text)
        if not result.permits("tool"):
            raise ValueError("Tool output blocked by GuardRail-Zero")
        return text
    if isinstance(value, dict):
        return {await inspect_output(k) if isinstance(k, str) else k: await inspect_output(v)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [await inspect_output(v) for v in value]
    if hasattr(value, "model_dump"):
        return await inspect_output(value.model_dump())
    if value is None or isinstance(value, (int, float, bool)):
        return value
    raise ValueError("Unsupported tool output type")

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

    def __init__(self, sanitize_outputs: bool = True, exempt_tools: Optional[Set[str]] = None):
        super().__init__()
        self.sanitize_outputs = sanitize_outputs
        self.exempt_tools = set(exempt_tools or ())

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

        # Only explicitly trusted tools owned by this server may bypass inspection
        if tool_name in self.exempt_tools:
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

        # Inspect text blocks and nested structured content before releasing them.
        if self.sanitize_outputs:
            try:
                for block in result.content or []:
                    if getattr(block, "type", None) != "text":
                        raise ValueError("Unsupported non-text tool output")
                    block.text = await inspect_output(block.text)
                result.structured_content = await inspect_output(result.structured_content)
            except ValueError:
                return ToolResult(content="Tool output blocked by GuardRail-Zero", is_error=True)

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

        if self.sanitize_outputs:
            try:
                execution_result = await inspect_output(execution_result)
            except ValueError:
                return {"isError": True, "content": [{"type": "text", "text": "Tool output blocked by GuardRail-Zero"}]}
        return execution_result
