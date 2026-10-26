"""Tenant settings: scan action, webhook, retention overrides (floors enforced by the model)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response

from ...contracts.admin import TenantSettings, TenantSettingsPatch
from ...contracts.errors import ApiError
from ...db.tenant_tx import tenant_tx
from ...tenants import registry
from ...tenants.auth import user_ctx
from ...tenants.context import TenantContext
from ...tenants.urls import UnsafeURL, avalidate_outbound_url
from ..http import require_if_match
from ..state import get_state

router = APIRouter(prefix="/v1/admin/settings", tags=["settings"])


def _etag(row: dict) -> str:  # type: ignore[type-arg]
    import json
    return registry.etag(row["id"], json.dumps(row["settings"], sort_keys=True))


@router.get("", response_model=TenantSettings)
async def get_settings(request: Request, response: Response,
                       ctx: TenantContext = Depends(user_ctx("viewer"))) -> TenantSettings:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        row = await registry.get_tenant(conn)
    response.headers["ETag"] = _etag(row)
    return TenantSettings.model_validate(row["settings"] or {})


@router.patch("", response_model=TenantSettings)
async def patch_settings(body: TenantSettingsPatch, request: Request, response: Response,
                         ctx: TenantContext = Depends(user_ctx("admin"))) -> TenantSettings:
    state = get_state(request)
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        row = await registry.get_tenant(conn)
        require_if_match(request, _etag(row))
        merged = TenantSettings.model_validate(row["settings"] or {}).model_dump(mode="json")
        for k, v in body.model_dump(mode="json", exclude_unset=True).items():
            merged[k] = v
        result = TenantSettings.model_validate(merged)       # re-validates floors and enums
        if result.webhook_url:
            try:
                await avalidate_outbound_url(result.webhook_url, allow_private=state.settings.private_hosts)
            except UnsafeURL as exc:
                raise ApiError("validation_failed", f"webhook_url rejected: {exc}",
                               errors=[{"path": "webhook_url", "message": str(exc)}]) from exc
        if result.judge_upstream_id:
            await registry.require_upstream(conn, result.judge_upstream_id)
        out = result.model_dump(mode="json")
        await registry.update_tenant_settings(conn, out)
        row["settings"] = out
    state.scanner.invalidate(ctx.tenant_id)
    response.headers["ETag"] = _etag(row)
    return result
