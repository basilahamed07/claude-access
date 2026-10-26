"""Shadow AI (design §2.4): ingest proxy / DNS logs, review the inventory of AI tools seen, mint ingest tokens."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import text

from ...contracts.errors import ApiError
from ...contracts.shadow import (
    MAX_BODY_BYTES,
    AiToolRead,
    AiToolUpdate,
    Classification,
    IngestBody,
    IngestResult,
    TokenCreate,
    TokenIssued,
    TokenRead,
)
from ...db.tenant_tx import tenant_tx
from ...tenants.auth import user_ctx
from ...tenants.context import TenantContext
from ...tenants.keys import issue_user_token
from ..state import get_state

router = APIRouter(tags=["shadow"])
_TOOL_COLS = ("id, domain, vendor, category, risk, classification, team, source, reason, hits, bytes_out, users_count, first_seen, last_seen, "
              "suggested_alternative")


async def _limit_body(request: Request) -> None:
    declared = request.headers.get("content-length", "")
    if not declared.isdigit() or int(declared) > MAX_BODY_BYTES:
        raise ApiError("payload_too_large", f"Send a Content-Length of at most {MAX_BODY_BYTES} bytes")


@router.post("/v1/ingest/logs", response_model=IngestResult, dependencies=[Depends(_limit_body)])
async def ingest_logs(body: IngestBody, request: Request, ctx: TenantContext = Depends(user_ctx("analyst"))) -> IngestResult:
    state = get_state(request)
    result = await state.shadow.ingest(ctx, source=body.source, fmt=body.format, batch_id=body.batch_id, team=body.team, lines=body.lines, records=body.records)
    return IngestResult(**result)


@router.get("/v1/admin/ai-tools", response_model=list[AiToolRead])
async def list_tools(request: Request, classification: Classification | None = None, team: str | None = Query(None, max_length=100),
                     limit: int = Query(200, ge=1, le=500), ctx: TenantContext = Depends(user_ctx("viewer"))) -> list[AiToolRead]:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        rows = (await conn.execute(text(
            f"select {_TOOL_COLS} from ai_tools_seen where (cast(:c as text) is null or classification = :c) and (cast(:tm as text) is null or team = :tm) "
            "order by (classification = 'blocked') desc, (classification = 'unknown') desc, last_seen desc limit :n"),
            {"c": classification, "tm": team, "n": limit})).mappings().all()
    return [AiToolRead(**r) for r in rows]


@router.patch("/v1/admin/ai-tools/{tool_id}", response_model=AiToolRead)
async def classify_tool(tool_id: UUID, body: AiToolUpdate, request: Request, ctx: TenantContext = Depends(user_ctx("admin"))) -> AiToolRead:
    row = await get_state(request).shadow.classify(ctx, tool_id, body.classification, body.suggested_alternative)
    if row is None:
        raise ApiError("not_found", "AI tool not found")
    return AiToolRead(**row)


# Ingest tokens are ordinary user tokens (`asu_…`) that belong to the person who minted them, so they carry that person's role and stop
# working when the person is disabled. They can only be minted from a signed-in session, never with another token.
@router.post("/v1/admin/tokens", status_code=201, response_model=TokenIssued)
async def create_token(body: TokenCreate, request: Request, ctx: TenantContext = Depends(user_ctx("analyst"))) -> TokenIssued:
    if ctx.auth_method != "session":
        raise ApiError("forbidden", "Tokens can only be created from a signed-in session")
    state = get_state(request)
    issued = issue_user_token(state.pepper)
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        row = (await conn.execute(text(
            "insert into user_tokens (tenant_id, user_id, prefix, token_hash, label) values (:t, :u, :p, :h, :l) returning id, prefix, label, created_at, revoked_at"),
            {"t": ctx.tenant_id, "u": ctx.actor_id, "p": issued.prefix, "h": issued.hash, "l": body.label})).mappings().one()
    return TokenIssued(**row, token=issued.plaintext)


@router.get("/v1/admin/tokens", response_model=list[TokenRead])
async def list_tokens(request: Request, ctx: TenantContext = Depends(user_ctx("analyst"))) -> list[TokenRead]:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        rows = (await conn.execute(text(
            "select id, prefix, label, created_at, revoked_at from user_tokens where user_id = :u order by created_at desc limit 100"),
            {"u": ctx.actor_id})).mappings().all()
    return [TokenRead(**r) for r in rows]


@router.delete("/v1/admin/tokens/{token_id}", status_code=204)
async def revoke_token(token_id: UUID, request: Request, ctx: TenantContext = Depends(user_ctx("analyst"))) -> Response:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        res = await conn.execute(text("update user_tokens set revoked_at = coalesce(revoked_at, now()) where id = :i and user_id = :u"),
                                 {"i": token_id, "u": ctx.actor_id})
    if res.rowcount == 0:
        raise ApiError("not_found", "Token not found")
    return Response(status_code=204)
