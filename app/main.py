"""
GuardRail-Zero: Main FastAPI Application Entrypoint.
Exposes OpenAI Reverse Proxy, MCP Security Gateway, and Health Monitoring.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.proxy.reverse_proxy import router as proxy_router
from app.mcp.server import mcp_app

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Self-Hosted SLM Firewall & MCP Security Gateway for Autonomous AI Agents",
    lifespan=mcp_app.lifespan
)

# CORS middleware for open agent frameworks
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount reverse proxy router for user traffic
app.include_router(proxy_router)

# Mount native FastMCP streamable HTTP / SSE endpoint for remote MCP agent clients
app.mount("/mcp", mcp_app)


@app.get("/")
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "online",
        "latency_target": "< 15ms p95",
        "interfaces": {
            "openai_proxy": "/v1/chat/completions",
            "mcp_sse": "/mcp",
            "health": "/health"
        }
    }


@app.get("/health")
async def health_check():
    """Healthcheck endpoint for Kubernetes / Docker container monitoring."""
    return {
        "status": "healthy",
        "tier0_heuristics": settings.ENABLE_TIER0_HEURISTICS,
        "tier1_slm": settings.ENABLE_TIER1_SLM,
        "entropy_threshold": settings.ENTROPY_THRESHOLD
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.GATEWAY_HOST,
        port=settings.GATEWAY_PORT,
        reload=settings.DEBUG
    )
