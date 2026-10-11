"""
OpenAI-Compatible Reverse Proxy Router.
Intercepts `/v1/chat/completions`, runs pre-flight cascade inspection,
and forwards clean traffic to the upstream LLM provider.
"""

import json
from collections import defaultdict
from fastapi import APIRouter, Request, HTTPException, status
from fastapi.responses import JSONResponse, StreamingResponse
import httpx

from app.config import settings
from app.core.cascade import SecurityCascadeEngine
from app.core.telemetry import audit_logger
from app.proxy.egress_scanner import EgressScanner

router = APIRouter(prefix="/v1", tags=["OpenAI Reverse Proxy"])
cascade = SecurityCascadeEngine()
egress_scanner = EgressScanner()


@router.post("/chat/completions")
async def chat_completions(request: Request):
    """
    OpenAI-compatible chat completions proxy endpoint.
    Performs pre-flight security evaluation before forwarding to upstream LLM.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload"
        )

    if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
        raise HTTPException(status_code=400, detail="messages must be a list")
    messages = body["messages"]
    if any(not isinstance(m, dict) for m in messages):
        raise HTTPException(status_code=400, detail="messages must contain objects")
    for message in messages:
        content = message.get("content")
        if content is not None and not isinstance(content, (str, list)):
            raise HTTPException(status_code=400, detail="Unsupported message content")
        if isinstance(content, list) and any(
            not isinstance(part, dict) or part.get("type") != "text" or not isinstance(part.get("text"), str)
            for part in content
        ):
            raise HTTPException(status_code=400, detail="Only text content blocks are supported")
        calls = message.get("tool_calls", [])
        if not isinstance(calls, list):
            raise HTTPException(status_code=400, detail="tool_calls must be a list")
        for call in calls:
            if not isinstance(call, dict) or not isinstance(call.get("function"), dict):
                raise HTTPException(status_code=400, detail="Unsupported tool call")
            if any(not isinstance(call["function"].get(field, ""), str) for field in ("name", "arguments")):
                raise HTTPException(status_code=400, detail="Tool fields must be strings")
        if "function_call" in message:
            raise HTTPException(status_code=400, detail="Legacy function_call is unsupported; use tool_calls")
    stream = body.get("stream", False)
    client_ip = request.client.host if request.client else "unknown"

    # 1. Pre-flight Security Cascade Inspection
    inspection = await cascade.inspect_messages(messages)

    # 2. Audit Event Logging
    audit_logger.log_event(
        endpoint="/v1/chat/completions",
        client_ip=client_ip,
        inspection=inspection,
        extra_metadata={"model": body.get("model"), "stream": stream}
    )

    # 3. Block malicious requests immediately
    if not inspection.permits("proxy"):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": {
                    "message": "Request blocked by GuardRail-Zero security policy.",
                    "type": "guardrail_security_violation",
                    "classification": inspection.classification.value,
                    "threat_type": inspection.threat_type,
                    "confidence": inspection.confidence,
                    "tier": inspection.tier,
                    "latency_ms": round(inspection.latency_ms, 2),
                    "details": inspection.details
                }
            }
        )

    # 4. Forward verified safe request to upstream LLM
    headers = {"Content-Type": "application/json"}
    if settings.UPSTREAM_API_KEY:
        headers["Authorization"] = f"Bearer {settings.UPSTREAM_API_KEY}"

    if stream:
        async def stream_generator():
            async with httpx.AsyncClient(timeout=60.0) as client:
                try:
                    async with client.stream(
                        "POST",
                        settings.UPSTREAM_LLM_URL,
                        json=body,
                        headers=headers
                    ) as response:
                        response.raise_for_status()
                        # Buffer until complete to detect secrets split across SSE deltas.
                        chunks = [chunk async for chunk in response.aiter_text()]
                        joined = "".join(chunks)
                        decoded = []
                        content_streams = defaultdict(list)
                        tool_streams = defaultdict(list)
                        for line in joined.splitlines():
                            if line.startswith("data:") and line[5:].strip() != "[DONE]":
                                event = json.loads(line[5:])
                                for choice in event.get("choices", []):
                                    delta = choice.get("delta", {})
                                    decoded.append(json.dumps(delta, ensure_ascii=False))
                                    content = delta.get("content")
                                    if isinstance(content, str):
                                        content_streams[choice.get("index", 0)].append(content)
                                    for call in delta.get("tool_calls", []):
                                        args = call.get("function", {}).get("arguments", "")
                                        if isinstance(args, str):
                                            tool_streams[(choice.get("index", 0), call.get("index", 0))].append(args)
                        assembled = ["".join(parts) for parts in (*content_streams.values(), *tool_streams.values())]
                        is_safe, leak_reason = egress_scanner.scan_chunk(joined + "".join(decoded + assembled))
                        if not is_safe:
                            yield f"data: {json.dumps({'error': leak_reason})}\n\n"
                        else:
                            yield joined
                except Exception as e:
                    yield f"data: {json.dumps({'error': 'Upstream response unavailable or invalid'})}\n\n"

        return StreamingResponse(stream_generator(), media_type="text/event-stream")

    # Non-streaming forward
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            resp = await client.post(
                settings.UPSTREAM_LLM_URL,
                json=body,
                headers=headers
            )
            data = resp.json()
            
            # Egress scan of full response
            choices = data.get("choices", [])
            full_text = json.dumps(choices, ensure_ascii=False)
            is_safe, leak_reason = egress_scanner.scan_chunk(full_text)
            if not is_safe:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"error": {"message": f"Egress blocked: {leak_reason}"}}
                )

            return JSONResponse(status_code=resp.status_code, content=data)
        except Exception:
            return JSONResponse(status_code=502, content={"error": {
                "type": "upstream_unavailable", "message": "Upstream response unavailable or invalid."}})
