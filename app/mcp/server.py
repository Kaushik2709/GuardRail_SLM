"""
Model Context Protocol (MCP) Server Endpoint.
Pure native FastMCP server exposing security tools and middleware
over stdio (CLI / Claude Desktop / Cursor / Goose) and SSE transports.
"""

from __future__ import annotations

import logging
from fastmcp import FastMCP
from app.config import settings
from app.mcp.interceptor import MCPInterceptor
from app.mcp.tools import register_security_tools

logger = logging.getLogger("guardrail.mcp.server")

# ==========================================
# FastMCP Native Server Initialization
# ==========================================

mcp = FastMCP(
    name="GuardRail-Zero",
    instructions=(
        "Self-Hosted SLM Firewall & MCP Security Gateway for Autonomous AI Agents. "
        "Provides memory inspection, pre-flight tool verification, and PII/credential redaction."
    ),
    version=settings.APP_VERSION,
)

# Attach Zero-Trust Security Middleware
# This server owns only these registered security functions. Execution servers
# must use the default empty exemption set; names alone are not trusted.
interceptor = MCPInterceptor(sanitize_outputs=True, exempt_tools=MCPInterceptor.EXEMPT_TOOLS)
mcp.add_middleware(interceptor)

# Register Core Security Tools
register_security_tools(mcp)

# FastMCP ASGI Application for streamable HTTP/SSE mounting if needed
mcp_app = mcp.http_app(path="/")


# ==========================================
# Standalone CLI / stdio Runner for Agent Hosts
# ==========================================

if __name__ == "__main__":
    import sys
    transport_mode = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] in ["stdio", "http", "sse"] else "stdio"
    # When running over stdio, stdout is strictly reserved for JSON-RPC messages.
    if transport_mode != "stdio":
        print(f"Starting GuardRail-Zero FastMCP Server on transport: {transport_mode}")
    else:
        logger.info(f"Starting GuardRail-Zero FastMCP Server on transport: {transport_mode}")
    mcp.run(transport=transport_mode)
