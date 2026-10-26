"""Provider connections. The API key is write-only; reads only say whether one is stored."""

from __future__ import annotations

import time
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response

from ...contracts.admin import (
    UpstreamCreate,
    UpstreamRead,
    UpstreamTestRequest,
    UpstreamTestResult,
    UpstreamUpdate,
)
from ...contracts.errors import ApiError
from ...db.tenant_tx import tenant_tx
from ...proxy.upstream import Api, UpstreamConfig
from ...tenants import registry
from ...tenants.auth import user_ctx
from ...tenants.context import TenantContext
from ...tenants.crypto import decrypt_secret, encrypt_secret
from ...tenants.urls import UnsafeURL, avalidate_outbound_url
from ..state import get_state

router = APIRouter(prefix="/v1/admin/upstreams", tags=["upstreams"])


async def _check_url(request: Request, url: str) -> str:
    try:
        return await avalidate_outbound_url(url, allow_private=get_state(request).settings.private_hosts)
    except UnsafeURL as exc:
        raise ApiError("validation_failed", f"base_url rejected: {exc}",
                       errors=[{"path": "base_url", "message": str(exc)}]) from exc


def _read(row: dict) -> UpstreamRead:  # type: ignore[type-arg]
    return UpstreamRead(**row)


@router.post("", status_code=201, response_model=UpstreamRead)
async def create_upstream(body: UpstreamCreate, request: Request,
                          ctx: TenantContext = Depends(user_ctx("admin"))) -> UpstreamRead:
    state = get_state(request)
    url = await _check_url(request, body.base_url)
    cipher = encrypt_secret(state.master_key, body.api_key) if body.api_key else None
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        row = await registry.create_upstream(
            conn, ctx.tenant_id, name=body.name, kind=body.kind, base_url=url, key_ciphertext=cipher,
            model_map={k: v.model_dump() for k, v in body.model_map.items()}, judge_model=body.judge_model)
    return _read(row)


@router.get("", response_model=list[UpstreamRead])
async def list_upstreams(request: Request, ctx: TenantContext = Depends(user_ctx("viewer"))) -> list[UpstreamRead]:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        return [_read(r) for r in await registry.list_upstreams(conn)]


@router.get("/{upstream_id}", response_model=UpstreamRead)
async def get_upstream(upstream_id: UUID, request: Request,
                       ctx: TenantContext = Depends(user_ctx("viewer"))) -> UpstreamRead:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        return _read(await registry.get_upstream(conn, upstream_id))


@router.patch("/{upstream_id}", response_model=UpstreamRead)
async def update_upstream(upstream_id: UUID, body: UpstreamUpdate, request: Request,
                          ctx: TenantContext = Depends(user_ctx("admin"))) -> UpstreamRead:
    state = get_state(request)
    fields = body.model_dump(exclude_unset=True)
    if "base_url" in fields:
        fields["base_url"] = await _check_url(request, fields["base_url"])
    if "api_key" in fields:
        key = fields.pop("api_key")
        fields["key_ciphertext"] = encrypt_secret(state.master_key, key) if key else None
    if "model_map" in fields and fields["model_map"] is not None:
        fields["model_map"] = {k: (v if isinstance(v, dict) else v.model_dump()) for k, v in fields["model_map"].items()}
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        return _read(await registry.update_upstream(conn, upstream_id, fields))


@router.delete("/{upstream_id}", status_code=204)
async def delete_upstream(upstream_id: UUID, request: Request,
                          ctx: TenantContext = Depends(user_ctx("admin"))) -> Response:
    async with tenant_tx(get_state(request).engine, ctx.tenant_id) as conn:
        await registry.delete_upstream(conn, upstream_id)
    return Response(status_code=204)


@router.post("/{upstream_id}/test", response_model=UpstreamTestResult)
async def test_upstream(upstream_id: UUID, request: Request, body: UpstreamTestRequest | None = None,
                        ctx: TenantContext = Depends(user_ctx("admin"))) -> UpstreamTestResult:
    """Send a 1-token request to verify URL, key and model. The provider's reply body is never returned."""
    state = get_state(request)
    async with tenant_tx(state.engine, ctx.tenant_id) as conn:
        row = await registry.get_upstream_secret(conn, upstream_id)
    cfg = UpstreamConfig(id=str(row["id"]), name=row["name"], kind=row["kind"], base_url=row["base_url"],
                         api_key=None, model_map=row["model_map"] or {}, judge_model=row["judge_model"])
    model = (body.model if body else None) or cfg.judge_model
    if not model and cfg.model_map:
        first: Any = cfg.model_map[sorted(cfg.model_map)[0]]        # JSONB has no key order: pick deterministically
        model = first.get("model") if isinstance(first, dict) else None
    if not model:
        raise ApiError("validation_failed", "Provide a model: none is configured on this upstream",
                       errors=[{"path": "model", "message": "required"}])
    api: Api = "anthropic" if cfg.kind == "anthropic" else "openai"
    key = decrypt_secret(state.master_key, row["key_ciphertext"]) if row["key_ciphertext"] else None
    started = time.monotonic()
    try:
        resp = await state.upstream.complete(
            cfg, api, {"model": model, "max_tokens": 1, "messages": [{"role": "user", "content": "ping"}]}, {}, key)
    except ApiError as exc:
        return UpstreamTestResult(ok=False, status=None, latency_ms=int((time.monotonic() - started) * 1000),
                                  error=exc.code)
    return UpstreamTestResult(ok=resp.status_code < 400, status=resp.status_code,
                              latency_ms=int((time.monotonic() - started) * 1000),
                              error=None if resp.status_code < 400 else f"http_{resp.status_code}")
