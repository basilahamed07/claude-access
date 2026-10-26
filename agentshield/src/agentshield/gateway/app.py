"""Application factory: one FastAPI app serving the data plane and the control plane."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..settings import Settings, get_settings
from .errors import RequestIdMiddleware, install_error_handlers
from .idempotency import IdempotencyMiddleware
from .routes import admin_agents, admin_settings, admin_upstreams, admin_users, auth, health
from .state import close_state, init_state


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        state = await init_state(app, settings)
        try:
            yield
        finally:
            await close_state(state)

    prod = settings.env == "prod"
    app = FastAPI(
        title="AgentShield", version="0.1.0", lifespan=lifespan,
        docs_url=None if prod else "/docs", redoc_url=None, openapi_url=None if prod else "/openapi.json",
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
    install_error_handlers(app)
    for module in (health, auth, admin_agents, admin_upstreams, admin_users, admin_settings):
        app.include_router(module.router)
    return app
