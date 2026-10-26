"""Process-wide dependencies, created once in the app lifespan and read from `app.state.s`."""

from __future__ import annotations

from dataclasses import dataclass

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, Request
from sqlalchemy.ext.asyncio import AsyncEngine

from ..db.engine import create_engine
from ..proxy.upstream import UpstreamClient
from ..settings import Settings


@dataclass
class AppState:
    settings: Settings
    engine: AsyncEngine
    redis: aioredis.Redis
    http: httpx.AsyncClient
    upstream: UpstreamClient
    pepper: bytes
    master_key: bytes
    jwt_secret: str
    session_secret: str


async def init_state(app: FastAPI, settings: Settings) -> AppState:
    http = httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=5.0), follow_redirects=False)
    state = AppState(
        settings=settings,
        engine=create_engine(settings.database_url),
        redis=aioredis.from_url(settings.redis_url, decode_responses=False),
        http=http,
        upstream=UpstreamClient(http, allow_private=settings.private_hosts, max_bytes=settings.upstream_max_bytes),
        pepper=settings.pepper_bytes,
        master_key=settings.master_key_bytes,
        jwt_secret=settings.jwt_secret_value,
        session_secret=settings.session_secret_value,
    )
    app.state.s = state
    return state


async def close_state(state: AppState) -> None:
    await state.http.aclose()
    await state.redis.aclose()
    await state.engine.dispose()


def get_state(request: Request) -> AppState:
    state: AppState = request.app.state.s
    return state
