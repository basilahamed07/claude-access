"""Agent registry, keys and connection snippets (api spec §A.3)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, Response

from ...contracts.admin import (
    AgentCreate,
    AgentRead,
    AgentUpdate,
    KeyIssued,
    KeyRead,
    Page,
    RotateRequest,
    Snippet,
)
from ...contracts.errors import ApiError
from ...db.tenant_tx import tenant_tx
from ...tenants import registry
from ...tenants.auth import user_ctx
from ...tenants.context import TenantContext
from ...tenants.keys import issue_agent_key
from ..http import require_if_match
from ..state import get_state

router = APIRouter(prefix="/v1/admin/agents", tags=["agents"])

Lang = Literal["python-openai", "python-anthropic", "curl", "claude-code"]


@router.post("", status_code=201, response_model=AgentRead)
async def create_agent(body: AgentCreate, request: Request, response: Response,
                       ctx: TenantContext = Depends(user_ctx("admin"))) -> AgentRead:
    state = get_state(request)
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        row = await registry.create_agent(conn, ctx.tenant_id, body.model_dump())
    response.headers["ETag"] = registry.agent_etag(row)
    return AgentRead(**row)


@router.get("", response_model=Page[AgentRead])
async def list_agents(request: Request, limit: int = Query(50, ge=1, le=200), cursor: str | None = None,
                      ctx: TenantContext = Depends(user_ctx("viewer"))) -> Page[AgentRead]:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        rows, nxt = await registry.list_agents(conn, limit, cursor)
    return Page[AgentRead](items=[AgentRead(**r) for r in rows], next_cursor=nxt)


@router.get("/{slug}", response_model=AgentRead)
async def get_agent(slug: str, request: Request, response: Response,
                    ctx: TenantContext = Depends(user_ctx("viewer"))) -> AgentRead:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        row = await registry.get_agent(conn, slug)
    response.headers["ETag"] = registry.agent_etag(row)
    return AgentRead(**row)


@router.patch("/{slug}", response_model=AgentRead)
async def update_agent(slug: str, body: AgentUpdate, request: Request, response: Response,
                       ctx: TenantContext = Depends(user_ctx("admin"))) -> AgentRead:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        current = await registry.get_agent(conn, slug)
        require_if_match(request, registry.agent_etag(current))
        row = await registry.update_agent(conn, slug, body.model_dump(exclude_unset=True), current["updated_at"])
    response.headers["ETag"] = registry.agent_etag(row)
    return AgentRead(**row)


@router.post("/{slug}/keys", status_code=201, response_model=KeyIssued)
async def issue_key(slug: str, request: Request, ctx: TenantContext = Depends(user_ctx("admin"))) -> KeyIssued:
    state = get_state(request)
    issued = issue_agent_key(state.pepper)
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        agent = await registry.get_agent(conn, slug)
        row = await registry.insert_agent_key(conn, ctx.tenant_id, agent["id"], issued)
    return KeyIssued(key=issued.plaintext, **row)


@router.get("/{slug}/keys", response_model=list[KeyRead])
async def list_keys(slug: str, request: Request, ctx: TenantContext = Depends(user_ctx("admin"))) -> list[KeyRead]:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        agent = await registry.get_agent(conn, slug)
        rows = await registry.list_agent_keys(conn, agent["id"])
    return [KeyRead(**r) for r in rows]


@router.post("/{slug}/keys/{key_id}/revoke", response_model=KeyRead)
async def revoke_key(slug: str, key_id: str, request: Request,
                     ctx: TenantContext = Depends(user_ctx("admin"))) -> KeyRead:
    from uuid import UUID
    try:
        kid = UUID(key_id)
    except ValueError as exc:
        raise ApiError("not_found", "Key not found") from exc
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        agent = await registry.get_agent(conn, slug)
        row = await registry.revoke_agent_key(conn, agent["id"], kid)
    return KeyRead(**row)


@router.post("/{slug}/keys/{key_id}/rotate", status_code=201, response_model=KeyIssued)
async def rotate_key(slug: str, key_id: str, body: RotateRequest, request: Request,
                     ctx: TenantContext = Depends(user_ctx("admin"))) -> KeyIssued:
    from uuid import UUID
    try:
        kid = UUID(key_id)
    except ValueError as exc:
        raise ApiError("not_found", "Key not found") from exc
    state = get_state(request)
    issued = issue_agent_key(state.pepper)
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        agent = await registry.get_agent(conn, slug)
        await registry.expire_key_after(conn, agent["id"], kid, body.overlap_seconds)
        row = await registry.insert_agent_key(conn, ctx.tenant_id, agent["id"], issued)
    return KeyIssued(key=issued.plaintext, **row)


@router.get("/{slug}/snippet", response_model=Snippet)
async def snippet(slug: str, request: Request, lang: Lang = "python-openai",
                  ctx: TenantContext = Depends(user_ctx("admin"))) -> Snippet:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        await registry.get_agent(conn, slug)
    base = str(request.base_url).rstrip("/")
    key = "ask_live_..."
    code = {
        "python-openai": (f'from openai import OpenAI\n\nclient = OpenAI(base_url="{base}/v1", api_key="{key}")\n'
                          '# optional: group calls into one session\n'
                          '# client = client.with_options(default_headers={"X-AgentShield-Session": "my-session"})\n'),
        "python-anthropic": (f'import anthropic\n\nclient = anthropic.Anthropic(base_url="{base}", api_key="{key}")\n'),
        "curl": (f'curl {base}/v1/chat/completions \\\n  -H "Authorization: Bearer {key}" \\\n'
                 '  -H "Content-Type: application/json" \\\n'
                 '  -d \'{"model":"<alias>","messages":[{"role":"user","content":"hello"}]}\'\n'),
        "claude-code": f'export ANTHROPIC_BASE_URL="{base}"\nexport ANTHROPIC_API_KEY="{key}"\nclaude\n',
    }[lang]
    return Snippet(lang=lang, code=code)


_ = (datetime, UTC)  # keep imports explicit for readers: timestamps come from the database
