"""The model proxy: Anthropic `/v1/messages` and OpenAI `/v1/chat/completions` (arch §3.1).

An agent changes only its base URL and key. Allowed traffic is forwarded unchanged; every
AgentShield-specific signal travels in `X-AgentShield-*` headers and the audit log.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from ...audit.events import make_event
from ...contracts.errors import ApiError
from ...contracts.events import EventType
from ...contracts.ids import new_trace_id
from ...db.tenant_tx import tenant_tx
from ...policy.budgets import BudgetStatus, BudgetUnavailable, price_micro_usd
from ...proxy.anthropic_stream import rewrite_anthropic, rewrite_anthropic_message
from ...proxy.openai_stream import rewrite_openai, rewrite_openai_message
from ...proxy.pipeline import ProxyCall
from ...proxy.sessions import SESSION_HEADER, USER_HEADER, first_user_message, session_key, upsert_session
from ...proxy.tools import ToolJudge, allow_all
from ...proxy.untrusted import extract_untrusted
from ...proxy.upstream import UpstreamConfig, api_matches_kind
from ...proxy.usage import StreamObserver, usage_from_message
from ...tenants import registry
from ...tenants.auth import agent_ctx
from ...tenants.context import TenantContext
from ...tenants.crypto import DecryptionError, decrypt_secret
from ..state import get_state

router = APIRouter(tags=["proxy"])
Api = Literal["anthropic", "openai"]
_ECHO_HEADERS = ("content-type", "retry-after", "request-id", "x-request-id")


async def read_limited(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise ApiError("payload_too_large", f"Request body exceeds {limit} bytes")
    size, chunks = 0, []
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise ApiError("payload_too_large", f"Request body exceeds {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _passthrough_key(request: Request) -> str:
    raw = request.headers.get("x-upstream-authorization", "").strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    if not raw:
        raise ApiError("unauthenticated", "This agent uses passthrough keys: send your provider key in "
                                          "the X-Upstream-Authorization header")
    return raw


def _echo(resp_headers: Any) -> dict[str, str]:
    return {k: v for k, v in resp_headers.items() if k.lower() in _ECHO_HEADERS and k.lower() != "content-type"}


async def handle_proxy(request: Request, ctx: TenantContext, api: Api) -> Response:
    state = get_state(request)
    raw = await read_limited(request, state.settings.proxy_max_body_bytes)
    try:
        body = json.loads(raw)
    except ValueError as exc:
        raise ApiError("validation_failed", "Request body must be valid JSON", status=400) from exc
    if not isinstance(body, dict) or not isinstance(body.get("messages"), list) or not body.get("model"):
        raise ApiError("validation_failed", "Request must include 'model' and a 'messages' list", status=400)

    trace_id = new_trace_id()
    request.state.trace_id = trace_id
    headers = {k.lower(): v for k, v in request.headers.items()}
    user_request = first_user_message(body["messages"])

    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        row = await registry.get_proxy_config(conn, ctx.actor_id)
        if row is None:
            raise ApiError("unauthenticated", "Agent no longer exists")
        if row["status"] != "active":
            raise ApiError("forbidden", "Agent is suspended")
        if row["upstream_id"] is None:
            raise ApiError("validation_failed", "This agent has no upstream configured", status=400)
        if not api_matches_kind(api, row["kind"]):
            raise ApiError("validation_failed", f"This endpoint speaks the {api} format but the agent's upstream "
                                                f"'{row['upstream_name']}' is of kind '{row['kind']}'", status=400)
        session = await upsert_session(
            conn, ctx.tenant_id, ctx.actor_id, session_key(headers, row["slug"], user_request),
            user_request, headers.get(USER_HEADER, "")[:200] or None)

    if row["key_mode"] == "passthrough":
        api_key: str | None = _passthrough_key(request)
    elif row["key_ciphertext"] is None:
        raise ApiError("upstream_error", "The agent's upstream has no API key configured")
    else:
        try:
            api_key = decrypt_secret(state.master_key, row["key_ciphertext"])
        except DecryptionError as exc:
            raise ApiError("internal", "Stored provider key cannot be decrypted") from exc

    cfg = UpstreamConfig(id=str(row["upstream_id"]), name=row["upstream_name"], kind=row["kind"],
                         base_url=row["base_url"], api_key=None, model_map=row["model_map"] or {},
                         judge_model=row["judge_model"])
    upstream_model, price_entry = cfg.resolve_model(str(body["model"]))
    untrusted_parts = extract_untrusted(api, body)
    budget_unavailable, admitted = False, None
    try:
        policy = await state.policies.get(state.engine, ctx.tenant_id, row["agent_id"], row["active_policy_version"])
        budgets = policy.doc.budgets
    except Exception:                                              # noqa: BLE001  (decisions will fail closed too)
        budgets = None
        await state.emitter.emit(make_event(ctx, trace_id, "gateway", EventType.error,
                                            "active policy could not be loaded: tool calls fail closed",
                                            session=session, severity="high"), {"component": "policy"})
    try:
        admitted = await state.budgets.admit(ctx.tenant_id, row["slug"], budgets)
    except BudgetUnavailable:
        budget_unavailable = True
        await state.emitter.emit(make_event(ctx, trace_id, "gateway", EventType.error,
                                            "budget service unavailable: only read-only tools are allowed",
                                            session=session, severity="high"), {"component": "budgets"})
    if admitted is not None and not admitted.ok:
        await state.emitter.emit(
            make_event(ctx, trace_id, "gateway", EventType.budget_exceeded, admitted.message(), session=session,
                       rule_id=f"budget:{admitted.exceeded}", severity="medium"),
            {"limit": admitted.exceeded, "retry_after": admitted.retry_after})
        code = "rate_limited" if admitted.exceeded == "rpm" else "budget_exceeded"
        raise ApiError(code, admitted.message(), headers={"Retry-After": str(admitted.retry_after)})
    limit_headers = _limit_headers(admitted)
    out_body = {**body, "model": upstream_model}
    request.state.session = session
    trace_header = {"X-AgentShield-Trace": trace_id, "X-AgentShield-Session": session.key}
    await state.emitter.emit(
        make_event(ctx, trace_id, "gateway", EventType.request_received,
                   f"{api} request to {row['upstream_name']} (model {body['model']}, stream={bool(body.get('stream'))})",
                   session=session),
        {"api": api, "model": str(body["model"]), "upstream_model": upstream_model, "stream": bool(body.get("stream")),
         "message_count": len(body["messages"]), "tool_result_parts": len(untrusted_parts),
         "tools_declared": len(body.get("tools") or []), "user_request": user_request})
    judge: ToolJudge = allow_all
    if state.judge_factory is not None:
        judge = state.judge_factory(ProxyCall(request=request, ctx=ctx, session=session, trace_id=trace_id,
                                              agent=row, api=api, user_request=user_request,
                                              budget_unavailable=budget_unavailable))

    if body.get("stream") is True:
        resp = await state.upstream.open_stream(cfg, api, out_body, headers, api_key)
        if resp.status_code != 200:
            data = await resp.aread()
            await resp.aclose()
            return _error_passthrough(request, api, resp.status_code, data, resp.headers, trace_header)
        rewrite = rewrite_anthropic if api == "anthropic" else rewrite_openai

        async def observed() -> AsyncIterator[bytes]:
            obs = StreamObserver(api)
            try:
                async for chunk in rewrite(state.upstream.iter_bytes(resp), judge):
                    obs.feed(chunk)
                    yield chunk
            finally:
                await state.emitter.emit(
                    make_event(ctx, trace_id, "gateway", EventType.model_response,
                               f"stream finished (stop_reason={obs.usage.stop_reason})", session=session),
                    {"status": 200, "stream": True, **obs.usage.as_payload()})
                await _record_usage(state, ctx, trace_id, session, row["slug"], price_entry, obs.usage)

        return StreamingResponse(observed(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", **trace_header,
                                          **limit_headers})

    resp = await state.upstream.complete(cfg, api, out_body, headers, api_key)
    if resp.status_code >= 400:
        return _error_passthrough(request, api, resp.status_code, resp.content, resp.headers, trace_header)
    media_type = resp.headers.get("content-type", "application/json")
    content = resp.content
    try:
        parsed = json.loads(content)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        rewrite_msg = rewrite_anthropic_message if api == "anthropic" else rewrite_openai_message
        new_body, changed = await rewrite_msg(parsed, judge)
        if changed:                                    # untouched answers stay byte-identical
            content = json.dumps(new_body, separators=(",", ":")).encode()
        usage = usage_from_message(api, new_body)
        await state.emitter.emit(
            make_event(ctx, trace_id, "gateway", EventType.model_response,
                       f"response (stop_reason={usage.stop_reason})", session=session),
            {"status": resp.status_code, "stream": False, "rewritten": changed, **usage.as_payload()})
        await _record_usage(state, ctx, trace_id, session, row["slug"], price_entry, usage)
    return Response(content, status_code=resp.status_code, media_type=media_type,
                    headers={**_echo(resp.headers), **trace_header, **limit_headers})


def _limit_headers(status: BudgetStatus | None) -> dict[str, str]:
    if status is None or not status.ok or status.rpm_remaining < 0:
        return {}
    return {"RateLimit-Limit": str(status.rpm_limit), "RateLimit-Remaining": str(status.rpm_remaining),
            "RateLimit-Reset": "60"}


async def _record_usage(state: Any, ctx: TenantContext, trace_id: str, session: Any, slug: str,
                        price_entry: dict[str, Any] | None, usage: Any) -> None:
    """Record tokens/cost for the daily budget. Never raises (a counting hiccup must not fail the request)."""
    try:
        cost, missing = price_micro_usd(price_entry, usage.input_tokens, usage.output_tokens)
        await state.budgets.record(ctx.tenant_id, slug, usage.input_tokens + usage.output_tokens, cost)
        if missing:
            day = __import__("datetime").datetime.now(__import__("datetime").UTC).strftime("%Y%m%d")
            if await state.redis.set(f"pricewarn:{ctx.tenant_id}:{slug}:{day}", "1", ex=86400, nx=True):
                await state.emitter.emit(
                    make_event(ctx, trace_id, "gateway", EventType.budget_price_missing,
                               "no price configured for this model; cost budgets cannot be enforced", session=session,
                               severity="low"), {"agent": slug})
    except BudgetUnavailable:
        pass
    except Exception:                                              # noqa: BLE001
        import logging
        logging.getLogger("agentshield").exception("could not record usage")


def _error_passthrough(request: Request, api: Api, status: int, data: bytes, resp_headers: Any,
                       trace_header: dict[str, str]) -> Response:
    """4xx from the provider is the agent's own problem: return it verbatim so SDK retry/backoff logic works.
    5xx is reported as a 502 in the provider's shape."""
    if status >= 500:
        raise ApiError("upstream_error", f"The model provider returned HTTP {status}")
    return Response(data, status_code=status, media_type=resp_headers.get("content-type", "application/json"),
                    headers={**_echo(resp_headers), **trace_header})


@router.post("/v1/messages")
async def anthropic_messages(request: Request, ctx: TenantContext = Depends(agent_ctx)) -> Response:
    return await handle_proxy(request, ctx, "anthropic")


@router.post("/v1/chat/completions")
async def openai_chat_completions(request: Request, ctx: TenantContext = Depends(agent_ctx)) -> Response:
    return await handle_proxy(request, ctx, "openai")


@router.get("/v1/models")
async def list_models(request: Request, ctx: TenantContext = Depends(agent_ctx)) -> JSONResponse:
    state = get_state(request)
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        row = await registry.get_proxy_config(conn, ctx.actor_id)
    aliases = sorted((row["model_map"] or {}).keys()) if row else []
    return JSONResponse({"object": "list", "data": [{"id": a, "object": "model", "owned_by": "agentshield"}
                                                    for a in aliases]})


_ = (SESSION_HEADER,)
