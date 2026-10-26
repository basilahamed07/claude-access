"""Injection-signature management: view the effective rules, add tenant rules, hot-reload (arch §2.2)."""

from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text

from ...contracts.admin import ScanRuleRead, ScanRulesPut, ScanRulesRead
from ...contracts.errors import ApiError
from ...db.tenant_tx import tenant_tx
from ...scan.rules import RuleSetError, load_ruleset
from ...tenants.auth import user_ctx
from ...tenants.context import TenantContext
from ..state import get_state

router = APIRouter(prefix="/v1/admin/scan-rules", tags=["scan-rules"])


async def _effective(request: Request, ctx: TenantContext) -> ScanRulesRead:
    state = get_state(request)
    rs = await state.rules.for_tenant(state.engine, ctx.tenant_id)
    default_ids = set(state.rules.base.by_id())
    return ScanRulesRead(version=rs.version, rules=[
        ScanRuleRead(id=r.id, category=r.category, weight=r.weight, description=r.description,
                     source="default" if r.id in default_ids and r is state.rules.base.by_id().get(r.id) else "tenant")
        for r in rs.rules])


@router.get("", response_model=ScanRulesRead)
async def get_rules(request: Request, ctx: TenantContext = Depends(user_ctx("viewer"))) -> ScanRulesRead:
    return await _effective(request, ctx)


@router.put("", response_model=ScanRulesRead)
async def put_rules(body: ScanRulesPut, request: Request, ctx: TenantContext = Depends(user_ctx("admin"))) -> ScanRulesRead:
    """Store the tenant's additional rules as a new active version (the previous version is kept, deactivated)."""
    try:
        load_ruleset(body.yaml)
    except RuleSetError as exc:
        raise ApiError("validation_failed", "Rule set is invalid",
                       errors=[{"path": "yaml", "message": m} for m in exc.errors]) from exc
    state = get_state(request)
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        await conn.execute(text("update scan_rule_sets set active = false where tenant_id = :t and active"),
                           {"t": ctx.tenant_id})
        await conn.execute(text(
            "insert into scan_rule_sets (tenant_id, version, yaml, sha256, active) values (:t, "
            "(select coalesce(max(version), 0) + 1 from scan_rule_sets where tenant_id = :t), :y, :h, true)"),
            {"t": ctx.tenant_id, "y": body.yaml, "h": hashlib.sha256(body.yaml.encode()).digest()})
    state.rules.invalidate(ctx.tenant_id)
    state.scanner.invalidate(ctx.tenant_id)
    return await _effective(request, ctx)


@router.delete("", response_model=ScanRulesRead)
async def reset_rules(request: Request, ctx: TenantContext = Depends(user_ctx("admin"))) -> ScanRulesRead:
    state = get_state(request)
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        await conn.execute(text("update scan_rule_sets set active = false where tenant_id = :t and active"),
                           {"t": ctx.tenant_id})
    state.rules.invalidate(ctx.tenant_id)
    state.scanner.invalidate(ctx.tenant_id)
    return await _effective(request, ctx)


@router.post("/reload", response_model=ScanRulesRead)
async def reload_rules(request: Request, ctx: TenantContext = Depends(user_ctx("admin"))) -> ScanRulesRead:
    get_state(request).rules.invalidate(ctx.tenant_id)
    return await _effective(request, ctx)
