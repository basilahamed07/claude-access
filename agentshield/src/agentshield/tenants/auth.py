"""FastAPI authentication dependencies.

Data plane: agent API key (`Authorization: Bearer ask_live_…` or `x-api-key`) or a 15-minute agent JWT.
Control plane: dashboard session cookie (+ CSRF header on unsafe methods) or a user token (`asu_…`).
A credential of one plane is rejected on the other (api spec §A.2, OWASP API5).
"""

from __future__ import annotations

import hmac
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from uuid import UUID

from fastapi import Request
from sqlalchemy import text

from ..contracts.errors import ApiError
from ..db.tenant_tx import system_tx, tenant_tx
from ..gateway.state import AppState, get_state
from .context import ROLE_RANK, Role, TenantContext
from .keys import (
    AGENT_PREFIX_LEN,
    USER_PREFIX_LEN,
    hash_secret,
    looks_like_agent_key,
    looks_like_user_token,
    verify_secret,
)
from .tokens import InvalidToken, verify_agent_jwt, verify_session

UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
_DUMMY_HASH = bytes(32)


def extract_token(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None
    return request.headers.get("x-api-key") or None


def _unauth(detail: str = "Missing or invalid credentials") -> ApiError:
    return ApiError("unauthenticated", detail, headers={"WWW-Authenticate": "Bearer"})


async def authenticate_agent_token(state: AppState, token: str, *, allow_jwt: bool = True) -> TenantContext:
    now = datetime.now(UTC)
    if looks_like_agent_key(token):
        async with system_tx(state.engine) as conn:
            row = (await conn.execute(text("select * from private.resolve_agent_key(:p)"),
                                      {"p": token[:AGENT_PREFIX_LEN]})).mappings().first()
        if row is None:
            verify_secret(state.pepper, token, _DUMMY_HASH)   # equalise timing
            raise _unauth()
        if not verify_secret(state.pepper, token, row["key_hash"]):
            raise _unauth()
        if row["revoked_at"] is not None or (row["expires_at"] is not None and row["expires_at"] <= now):
            raise _unauth("Key revoked or expired")
        if row["agent_status"] != "active":
            raise ApiError("forbidden", "Agent is suspended")
        return TenantContext(tenant_id=row["tenant_id"], actor="agent", actor_id=row["agent_id"],
                             agent_slug=row["agent_slug"], auth_method="key")
    if allow_jwt and token.count(".") == 2:
        try:
            claims = verify_agent_jwt(state.jwt_secret, token)
        except InvalidToken as exc:
            raise _unauth("Invalid or expired token") from exc
        return TenantContext(tenant_id=UUID(claims.tenant_id), actor="agent", actor_id=UUID(claims.agent_id),
                             agent_slug=claims.agent_slug, auth_method="jwt")
    raise _unauth()


async def agent_ctx(request: Request) -> TenantContext:
    token = extract_token(request)
    if not token:
        raise _unauth()
    ctx = await authenticate_agent_token(get_state(request), token)
    request.state.ctx = ctx
    return ctx


async def agent_key_ctx(request: Request) -> TenantContext:
    """Like `agent_ctx` but only a long-lived key (used by /v1/token: a JWT cannot mint a JWT)."""
    token = extract_token(request)
    if not token:
        raise _unauth()
    ctx = await authenticate_agent_token(get_state(request), token, allow_jwt=False)
    request.state.ctx = ctx
    return ctx


async def _user_from_session(request: Request, state: AppState, cookie: str) -> TenantContext:
    try:
        claims = verify_session(state.session_secret, cookie)
    except InvalidToken as exc:
        raise _unauth("Session expired") from exc
    if request.method in UNSAFE:
        sent = request.headers.get("x-csrf-token", "")
        if not sent or not hmac.compare_digest(sent, str(claims.get("csrf", ""))):
            raise ApiError("forbidden", "Missing or invalid CSRF token")
    tenant_id, user_id = UUID(claims["tid"]), UUID(claims["sub"])
    async with tenant_tx(state.engine, tenant_id) as conn:
        row = (await conn.execute(text("select role, disabled_at from users where id = :u"),
                                  {"u": user_id})).mappings().first()
    if row is None or row["disabled_at"] is not None:
        raise _unauth("Account disabled")
    return TenantContext(tenant_id=tenant_id, actor="user", actor_id=user_id, role=row["role"],
                         auth_method="session")


async def _user_from_token(state: AppState, token: str) -> TenantContext:
    async with system_tx(state.engine) as conn:
        row = (await conn.execute(text("select * from private.resolve_user_token(:p)"),
                                  {"p": token[:USER_PREFIX_LEN]})).mappings().first()
    if row is None:
        hash_secret(state.pepper, token)
        raise _unauth()
    if not verify_secret(state.pepper, token, row["token_hash"]) or row["revoked_at"] is not None:
        raise _unauth()
    return TenantContext(tenant_id=row["tenant_id"], actor="user", actor_id=row["user_id"], role=row["role"],
                         auth_method="token")


def user_ctx(minimum: Role = "viewer") -> Callable[[Request], Awaitable[TenantContext]]:
    async def dependency(request: Request) -> TenantContext:
        state = get_state(request)
        token = extract_token(request)
        if token and looks_like_user_token(token):
            ctx = await _user_from_token(state, token)
        elif (cookie := request.cookies.get("as_session")) and not token:
            ctx = await _user_from_session(request, state, cookie)
        else:
            raise _unauth()
        if ROLE_RANK[ctx.role or "viewer"] < ROLE_RANK[minimum]:
            raise ApiError("forbidden", f"Requires role {minimum}")
        request.state.ctx = ctx
        return ctx

    dependency.__name__ = f"user_ctx_{minimum}"
    dependency.required_role = minimum  # type: ignore[attr-defined]
    return dependency
