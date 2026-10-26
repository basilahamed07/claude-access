"""Application factory: one FastAPI app serving the data plane and the control plane."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from opentelemetry.sdk.trace import TracerProvider

from ..contracts.errors import Problem
from ..observability import SecurityHeadersMiddleware, instrument_clients, setup_observability
from ..settings import Settings, get_settings
from .errors import RequestIdMiddleware, install_error_handlers
from .idempotency import IdempotencyMiddleware
from .routes import (
    admin_agents,
    admin_alerts,
    admin_events,
    admin_incidents,
    admin_mcp,
    admin_policies,
    admin_scan_rules,
    admin_sessions,
    admin_settings,
    admin_shadow,
    admin_upstreams,
    admin_users,
    approvals,
    auth,
    check,
    health,
    mcp_proxy,
    proxy,
    scan,
)
from .state import close_state, init_state

_ERRORS = {400: "Malformed request", 401: "Missing or invalid credentials", 403: "Not allowed for this credential or role",
           404: "Not found (also returned for other tenants' resources)", 409: "Conflict", 412: "Precondition failed (stale ETag)",
           413: "Request too large", 422: "Validation failed", 428: "If-Match required", 429: "Rate limit or budget exceeded",
           500: "Internal error", 502: "Upstream provider error", 504: "Upstream provider timed out"}
PROBLEM_RESPONSES: dict[int | str, dict[str, Any]] = {
    code: {"description": text, "model": Problem,
           "content": {"application/problem+json": {"schema": {"$ref": "#/components/schemas/Problem"}}}}
    for code, text in _ERRORS.items()}


def create_app(settings: Settings | None = None, tracer_provider: TracerProvider | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        state = await init_state(app, settings)
        instrument_clients(state, tracer_provider)
        sweeper = asyncio.create_task(state.approvals.sweep_forever(settings.approval_sweep_seconds))
        try:
            yield
        finally:
            sweeper.cancel()
            await asyncio.gather(sweeper, return_exceptions=True)
            await state.approvals.drain_notifications()
            await close_state(state)

    prod = settings.env == "prod"
    app = FastAPI(
        title="AgentShield", version="0.1.0", lifespan=lifespan,
        responses=PROBLEM_RESPONSES, docs_url=None if prod else "/docs", redoc_url=None, openapi_url=None if prod else "/openapi.json",
    )
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    app.add_middleware(IdempotencyMiddleware)
    app.add_middleware(
        CORSMiddleware, allow_origins=origins, allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "Idempotency-Key", "If-Match",
                       "X-AgentShield-Session", "X-AgentShield-User"],
        expose_headers=["ETag", "X-Request-Id", "X-AgentShield-Trace"],
    )
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(SecurityHeadersMiddleware, hsts=prod or settings.cookie_secure)
    setup_observability(app, settings, tracer_provider)
    install_error_handlers(app)
    for module in (health, auth, check, scan, approvals, proxy, admin_events, admin_sessions, admin_incidents, admin_alerts, admin_mcp, admin_shadow, mcp_proxy, admin_agents, admin_policies, admin_scan_rules, admin_upstreams, admin_users, admin_settings):
        app.include_router(module.router)
    return app
