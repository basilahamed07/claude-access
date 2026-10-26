"""Versioned policies per agent (api spec §A.3)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ...contracts.admin import PolicyVersionCreate, PolicyVersionRead
from ...contracts.errors import ApiError
from ...db.tenant_tx import tenant_tx
from ...policy import store
from ...policy.loader import PolicyError, parse_policy
from ...tenants import registry
from ...tenants.auth import user_ctx
from ...tenants.context import TenantContext
from ..http import require_if_match
from ..state import get_state

router = APIRouter(prefix="/v1/admin/agents/{slug}/policy", tags=["policies"])


def _policy_error(exc: PolicyError) -> ApiError:
    first = exc.errors[0]
    return ApiError("policy_invalid", f"Line {first.line}: {first.message}", errors=[e.as_dict() for e in exc.errors])


@router.get("/versions", response_model=list[PolicyVersionRead])
async def list_versions(slug: str, request: Request,
                        ctx: TenantContext = Depends(user_ctx("viewer"))) -> list[PolicyVersionRead]:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        agent = await registry.get_agent(conn, slug)
        rows = await store.list_versions(conn, agent["id"], agent["active_policy_version"])
    return [PolicyVersionRead(**r) for r in rows]


@router.post("/versions", status_code=201, response_model=PolicyVersionRead)
async def create_version(slug: str, body: PolicyVersionCreate, request: Request,
                         ctx: TenantContext = Depends(user_ctx("admin"))) -> PolicyVersionRead:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        agent = await registry.get_agent(conn, slug)                 # unknown agent -> 404 before anything else
        try:
            policy = parse_policy(body.yaml)
        except PolicyError as exc:
            raise _policy_error(exc) from exc
        if policy.doc.agent and policy.doc.agent != slug:
            raise ApiError("policy_invalid", f"Policy says agent '{policy.doc.agent}' but is being saved for '{slug}'",
                           errors=[{"line": 1, "path": "agent", "message": f"must be '{slug}' or omitted"}])
        row = await store.create_version(conn, ctx.tenant_id, agent["id"], body.yaml, policy, ctx.actor_id, body.version)
        if body.activate:
            await store.activate(conn, slug, row["version"], agent["updated_at"])
        row["active"] = body.activate
    return PolicyVersionRead(**row)


@router.get("/versions/{version}", response_model=PolicyVersionRead)
async def get_version(slug: str, version: int, request: Request,
                      ctx: TenantContext = Depends(user_ctx("viewer"))) -> PolicyVersionRead:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        agent = await registry.get_agent(conn, slug)
        row = await store.get_version(conn, agent["id"], version)
    return PolicyVersionRead(**row, active=row["version"] == agent["active_policy_version"])


@router.post("/versions/{version}/activate", response_model=PolicyVersionRead)
async def activate_version(slug: str, version: int, request: Request,
                           ctx: TenantContext = Depends(user_ctx("admin"))) -> PolicyVersionRead:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        agent = await registry.get_agent(conn, slug)
        require_if_match(request, registry.agent_etag(agent))
        row = await store.get_version(conn, agent["id"], version)
        await store.activate(conn, slug, version, agent["updated_at"])
    return PolicyVersionRead(**row, active=True)
