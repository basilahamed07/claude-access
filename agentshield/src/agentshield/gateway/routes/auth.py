"""Sign-up, login/logout, session info, agent key -> JWT exchange."""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from ...contracts.admin import LoginRequest, LoginResponse, MeResponse, SignupRequest, TokenResponse
from ...contracts.errors import ApiError
from ...db.tenant_tx import system_tx, tenant_tx
from ...tenants.auth import agent_key_ctx, user_ctx
from ...tenants.context import TenantContext
from ...tenants.passwords import hash_password, verify_password
from ...tenants.registry import is_unique_violation
from ...tenants.tokens import (
    AGENT_JWT_TTL,
    SESSION_TTL,
    InvalidToken,
    mint_agent_jwt,
    mint_session,
    verify_session,
)
from ..state import get_state

router = APIRouter(tags=["auth"])
MAX_FAILS = 5
LOCK_SECONDS = 15 * 60


def _slugify(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "tenant"
    return f"{base}-{secrets.token_hex(2)}"


async def _rate_limit(request: Request, bucket: str, limit: int, window: int) -> None:
    redis = get_state(request).redis
    key = f"rl:{bucket}:{request.client.host if request.client else 'unknown'}"
    n = await redis.incr(key)
    if n == 1:
        await redis.expire(key, window)
    if n > limit:
        raise ApiError("rate_limited", "Too many requests", headers={"Retry-After": str(window)})


@router.post("/v1/signup", status_code=201)
async def signup(body: SignupRequest, request: Request) -> dict[str, str]:
    state = get_state(request)
    if state.settings.signup == "closed":
        raise ApiError("forbidden", "Sign-up is disabled on this installation")
    await _rate_limit(request, "signup", 10, 3600)
    slug = body.slug or _slugify(body.tenant_name)
    try:
        async with system_tx(state.engine) as conn:
            tid = (await conn.execute(text("select private.create_tenant(:n, :s, :e, :p)"),
                                      {"n": body.tenant_name, "s": slug, "e": body.email,
                                       "p": hash_password(body.password)})).scalar_one()
    except (IntegrityError, DBAPIError) as exc:
        if isinstance(exc, IntegrityError) and is_unique_violation(exc):
            raise ApiError("conflict", "That workspace name or e-mail is already registered") from exc
        if "unique" in str(exc).lower():
            raise ApiError("conflict", "That workspace name or e-mail is already registered") from exc
        raise
    return {"tenant_id": str(tid), "slug": slug}


@router.post("/v1/auth/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request, response: Response) -> LoginResponse:
    state = get_state(request)
    email = str(body.email).lower()
    fail_key = f"loginfail:{hashlib.sha256(email.encode()).hexdigest()[:32]}"
    fails = int(await state.redis.get(fail_key) or 0)
    if fails >= MAX_FAILS:
        raise ApiError("rate_limited", "Too many failed attempts. Try again in 15 minutes.",
                       headers={"Retry-After": str(LOCK_SECONDS)})
    async with system_tx(state.engine) as conn:
        row = (await conn.execute(text("select * from private.resolve_login(:e)"), {"e": email})).mappings().first()
    now = datetime.now(UTC)
    ok = verify_password(row["password_hash"] if row else None, body.password)
    if row is not None and (row["disabled_at"] is not None or (row["locked_until"] and row["locked_until"] > now)):
        ok = False
    if not ok:
        n = await state.redis.incr(fail_key)
        await state.redis.expire(fail_key, LOCK_SECONDS)
        if row is not None:
            async with tenant_tx(state.engine, row["tenant_id"]) as conn:
                await conn.execute(text(
                    "update users set failed_logins = failed_logins + 1, "
                    "locked_until = case when failed_logins + 1 >= :m then :lu else locked_until end where id = :u"),
                    {"m": MAX_FAILS, "lu": now + timedelta(seconds=LOCK_SECONDS), "u": row["user_id"]})
        if n >= MAX_FAILS:
            raise ApiError("rate_limited", "Too many failed attempts. Try again in 15 minutes.",
                           headers={"Retry-After": str(LOCK_SECONDS)})
        raise ApiError("unauthenticated", "Invalid e-mail or password")
    assert row is not None
    await state.redis.delete(fail_key)
    async with tenant_tx(state.engine, row["tenant_id"]) as conn:
        await conn.execute(text("update users set failed_logins = 0, locked_until = null where id = :u"),
                           {"u": row["user_id"]})
    csrf = secrets.token_urlsafe(24)
    token = mint_session(state.session_secret, user_id=str(row["user_id"]), tenant_id=str(row["tenant_id"]),
                         role=row["role"], csrf=csrf)
    response.set_cookie("as_session", token, httponly=True, secure=state.settings.cookie_secure,
                        samesite="lax", max_age=SESSION_TTL, path="/")
    return LoginResponse(user_id=row["user_id"], tenant_id=row["tenant_id"], role=row["role"], csrf_token=csrf)


@router.post("/v1/auth/logout", status_code=204)
async def logout(response: Response) -> None:
    response.delete_cookie("as_session", path="/")


@router.get("/v1/auth/me", response_model=MeResponse)
async def me(request: Request, ctx: TenantContext = Depends(user_ctx("viewer"))) -> MeResponse:
    state = get_state(request)
    csrf = None
    if cookie := request.cookies.get("as_session"):
        try:
            csrf = str(verify_session(state.session_secret, cookie).get("csrf"))
        except InvalidToken:
            csrf = None
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        email = (await conn.execute(text("select email from users where id = :u"), {"u": ctx.actor_id})).scalar_one()
    return MeResponse(user_id=ctx.actor_id, tenant_id=ctx.tenant_id, email=str(email), role=ctx.role or "viewer",
                      csrf_token=csrf)


@router.post("/v1/token", response_model=TokenResponse)
async def exchange_token(request: Request, ctx: TenantContext = Depends(agent_key_ctx)) -> TokenResponse:
    state = get_state(request)
    token = mint_agent_jwt(state.jwt_secret, tenant_id=str(ctx.tenant_id), agent_id=str(ctx.actor_id),
                           agent_slug=ctx.agent_slug or "")
    return TokenResponse(access_token=token, expires_in=AGENT_JWT_TTL)
