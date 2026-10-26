"""MCP proxy mode (design §2.3a): one Streamable-HTTP MCP endpoint per agent in front of the tenant's approved servers.

tools/list shows the approved tools (as approved, namespaced `server__tool`); tools/call asks the policy first, forwards only if allowed,
and scans what comes back before the agent sees it.
"""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse

from ...audit.events import make_event
from ...contracts.decision import Decision
from ...contracts.errors import ApiError
from ...contracts.events import EventType
from ...contracts.ids import new_trace_id
from ...db.tenant_tx import tenant_tx
from ...mcp import registry as mcp_registry
from ...mcp.analysis import namespaced, split_namespaced
from ...mcp.client import McpError
from ...observability import link_trace
from ...policy.budgets import BudgetUnavailable
from ...policy.decide import AgentInfo, ask_text, block_text
from ...proxy.guard import wrap
from ...proxy.sessions import SessionRef, upsert_session
from ...proxy.untrusted import UntrustedPart
from ...tenants import registry
from ...tenants.auth import agent_ctx
from ...tenants.context import TenantContext
from ..state import get_state

router = APIRouter(tags=["mcp-proxy"])
MAX_BODY = 1_000_000
PROTOCOL = "2025-03-26"


def _ok(rid: Any, result: dict[str, Any], headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": result}, headers=headers)


def _err(rid: Any, code: int, message: str) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}})


def _text(text: str, *, error: bool) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": error}


@router.post("/mcp/{agent_slug}")
async def mcp_endpoint(agent_slug: str, request: Request, ctx: TenantContext = Depends(agent_ctx)) -> Response:
    state = get_state(request)
    if agent_slug != ctx.agent_slug:
        raise ApiError("credential_mismatch", f"This credential belongs to agent '{ctx.agent_slug}', not '{agent_slug}'")
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise ApiError("payload_too_large", "MCP message too large")
    try:
        msg = json.loads(raw)
    except ValueError:
        return _err(None, -32700, "Parse error")
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return _err(msg.get("id") if isinstance(msg, dict) else None, -32600, "Invalid request (batches are not supported)")
    method, rid = msg["method"], msg.get("id")
    params: dict[str, Any] = msg["params"] if isinstance(msg.get("params"), dict) else {}
    if rid is None:                                            # notification
        return Response(status_code=202)
    if method == "initialize":
        sid = f"ms-{secrets.token_urlsafe(18)}"
        return _ok(rid, {"protocolVersion": PROTOCOL, "capabilities": {"tools": {"listChanged": False}},
                         "serverInfo": {"name": "agentshield", "version": "0.1"}}, {"Mcp-Session-Id": sid})
    if method == "ping":
        return _ok(rid, {})
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        row = await registry.get_proxy_config(conn, ctx.actor_id)
        servers = await mcp_registry.usable_servers(conn)
        names = {r["id"]: (await mcp_registry.get(conn, r["id"]))["name"] for r in servers}
    if row is None or row["status"] != "active":
        raise ApiError("forbidden", "Agent is suspended or no longer exists")
    live = []
    for s in servers:
        s = {**s, "name": names[s["id"]]}
        if await state.mcp.check_drift(ctx, s, use_cache=True) != "drifted":
            live.append(s)                                   # a server that changed after approval is suspended and disappears
    if method == "tools/list":
        tools = []
        for s in live:
            allowed = set(s["allowed_tools"]) if s["allowed_tools"] is not None else None
            for t in s["tools"] or []:
                if allowed is None or t["name"] in allowed:
                    tools.append({**t, "name": namespaced(s["name"], t["name"])})
        return _ok(rid, {"tools": tools})
    if method == "tools/call":
        return await _call(state, request, ctx, row, live, rid, params)
    return _err(rid, -32601, f"Method not found: {method}")


async def _call(state: Any, request: Request, ctx: TenantContext, row: dict[str, Any], servers: list[dict[str, Any]], rid: Any, params: dict[str, Any]) -> Response:
    full = str(params.get("name", ""))
    arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
    parts = split_namespaced(full)
    trace_id = new_trace_id()
    link_trace(trace_id)
    server = next((s for s in servers if parts and s["name"] == parts[0]), None)
    if parts is None or server is None:
        return _err(rid, -32602, f"Unknown tool: {full[:80]}")
    tool = parts[1]
    allowed = set(server["allowed_tools"]) if server["allowed_tools"] is not None else None
    if tool not in {t["name"] for t in server["tools"] or []} or (allowed is not None and tool not in allowed):
        return _err(rid, -32602, f"Unknown tool: {full[:80]}")
    try:
        rate = await state.budgets.admit(ctx.tenant_id, ctx.agent_slug or "", None, scope=":mcp", count_call=False, default_rpm=state.settings.check_rpm)
        if not rate.ok:
            return _ok(rid, _text(f"Rate limit reached. {rate.message()}", error=True))
    except BudgetUnavailable:
        pass
    key = request.headers.get("mcp-session-id") or request.headers.get("x-agentshield-session") or f"mcp-{ctx.agent_slug}-{datetime.now(UTC):%Y%m%d}"
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        session: SessionRef = await upsert_session(conn, ctx.tenant_id, ctx.actor_id, key[:200], None, request.headers.get("x-agentshield-user"))
    resp = await state.enforcer.decide(ctx, AgentInfo.from_row(row), session, tool, arguments, trace_id=trace_id, source="mcp", server=server["name"])
    if resp.decision is not Decision.allow:
        text = block_text(resp) if resp.decision is Decision.block else ask_text(resp)
        await state.emitter.emit(make_event(ctx, trace_id, "mcp", EventType.mcp_tool_call, f"{server['name']}__{tool} was not forwarded ({resp.decision.value})", session=session,
                                            decision=resp.decision, rule_id=resp.rule_id, reason=resp.reason, severity="medium"),
                                 {"server": server["name"], "tool": tool, "forwarded": False, "text": text})
        return _ok(rid, _text(text, error=True))
    try:
        result = await state.mcp.client({**server, "url": server["url"], "auth_ciphertext": server["auth_ciphertext"]}).call_tool(tool, arguments)
    except McpError as exc:
        await state.emitter.emit(make_event(ctx, trace_id, "mcp", EventType.error, f"MCP server {server['name']} failed a call", session=session, severity="medium"),
                                 {"server": server["name"], "tool": tool, "error": str(exc)})
        return _ok(rid, _text(f"The MCP server '{server['name']}' could not complete this call.", error=True))
    return _ok(rid, await _guard_result(state, ctx, session, trace_id, server["name"], tool, result))


async def _guard_result(state: Any, ctx: TenantContext, session: SessionRef, trace_id: str, server: str, tool: str, result: dict[str, Any]) -> dict[str, Any]:
    """Scan what a server returned before the agent reads it: hostile text is removed or withheld, the rest is marked as untrusted data."""
    tcfg = await state.scanner.tenant_cfg(ctx.tenant_id)
    out: list[Any] = []
    verdicts: list[str] = []
    for i, block in enumerate(result.get("content") or []):
        if not (isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str)):
            out.append(block)
            continue
        part = UntrustedPart(message_index=0, block_index=i, source=f"mcp:{server}", id=f"{tool}#{i}", text=block["text"])
        res = await state.scanner.scan_content(ctx, trace_id=trace_id, session=session, source=part.source, content_id=part.id, text_=part.text)
        verdicts.append(res.verdict)
        text = res.sanitized_text if res.sanitized_text is not None else block["text"]
        out.append({**block, "text": wrap(text, part, res.verdict) if tcfg.settings.mark_untrusted else text})
    await state.emitter.emit(make_event(ctx, trace_id, "mcp", EventType.mcp_tool_call, f"{server}__{tool} forwarded", session=session, decision=Decision.allow,
                                        severity="high" if "malicious" in verdicts else "info"),
                             {"server": server, "tool": tool, "forwarded": True, "result_verdicts": verdicts, "is_error": bool(result.get("isError"))})
    return {**result, "content": out}
