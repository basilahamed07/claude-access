from __future__ import annotations

import hmac
import logging
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from ...db.tenant_tx import system_tx
from ...observability import APPROVALS_PENDING, AUDIT_LAG, REGISTRY, STREAM_PENDING, client_is_internal
from ..state import get_state

router = APIRouter(tags=["health"])
log = logging.getLogger("agentshield.health")


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request) -> JSONResponse:
    state = get_state(request)
    checks: dict[str, Any] = {}
    try:
        async with state.engine.connect() as conn:
            await conn.execute(text("select 1"))
        checks["database"] = "ok"
    except Exception:  # noqa: BLE001
        checks["database"] = "down"
    try:
        await state.redis.ping()
        checks["redis"] = "ok"
    except Exception:  # noqa: BLE001
        checks["redis"] = "down"
    clf = state.classifier
    checks["classifier"] = clf.status                       # ok | disabled | degraded: never silently "clean"
    if clf.status == "degraded":
        checks["classifier_reason"] = clf.reason[:200]
    backlog = await stream_backlog(state)
    if backlog is not None:
        checks["audit_backlog"] = backlog
        checks["audit_lag_seconds"] = round(AUDIT_LAG._value.get(), 1)
        checks["audit_worker"] = "ok" if backlog < state.settings.audit_backlog_warn else "lagging"
    ok = all(v == "ok" for k, v in checks.items() if k in {"database", "redis"})
    return JSONResponse({"status": "ok" if ok else "unavailable", **checks}, status_code=200 if ok else 503)


async def stream_backlog(state: object) -> int | None:
    """Audit events published but not yet written (pending for a worker, or not yet delivered). None if unknown."""
    from ...audit.emitter import STREAM
    from ...audit.worker import GROUP
    redis = state.redis  # type: ignore[attr-defined]
    try:
        groups = await redis.xinfo_groups(STREAM)
    except Exception as exc:                                      # noqa: BLE001
        return 0 if "no such key" in str(exc).lower() else None      # no stream yet = nothing waiting; else Redis is down
    for g in groups:
        name = g.get("name") or g.get(b"name")
        if (name.decode() if isinstance(name, bytes) else name) == GROUP:
            pending = int(g.get("pending") or g.get(b"pending") or 0)
            lag = g.get("lag") if "lag" in g else g.get(b"lag")
            return pending + int(lag or 0)
    return int(await redis.xlen(STREAM))


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> Response:
    """Prometheus scrape endpoint. Internal network only; a bearer token can be required on top."""
    state = get_state(request)
    if not client_is_internal(request, state.settings):
        return Response(status_code=404)
    token = state.settings.metrics_token
    if token and not hmac.compare_digest(request.headers.get("authorization", ""), f"Bearer {token}"):
        return Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})
    try:
        async with system_tx(state.engine) as conn:
            APPROVALS_PENDING.set(int((await conn.execute(text("select private.count_pending_approvals()"))).scalar_one()))
    except Exception:                                             # noqa: BLE001
        log.warning("could not count pending approvals for /metrics")
    backlog = await stream_backlog(state)
    STREAM_PENDING.set(backlog or 0)
    return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)
