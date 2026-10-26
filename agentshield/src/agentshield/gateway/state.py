"""Process-wide dependencies, created once in the app lifespan and read from `app.state.s`."""

from __future__ import annotations

from dataclasses import dataclass

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, Request
from sqlalchemy.ext.asyncio import AsyncEngine

from ..audit.emitter import Emitter
from ..audit.spool import Spool
from ..db.engine import create_engine
from ..mcp.service import McpService
from ..policy.approvals import ApprovalsService
from ..policy.budgets import BudgetTracker
from ..policy.cache import PolicyCache
from ..policy.decide import PolicyEnforcer
from ..proxy.pipeline import JudgeFactory
from ..proxy.upstream import UpstreamClient
from ..scan.classifier import ClassifierHandle, load_classifier
from ..scan.pipeline import ScanService
from ..scan.rules import RuleStore
from ..settings import Settings
from ..tenants.safe_http import SafeTransport


@dataclass
class AppState:
    settings: Settings
    engine: AsyncEngine
    redis: aioredis.Redis
    http: httpx.AsyncClient
    upstream: UpstreamClient
    emitter: Emitter
    budgets: BudgetTracker
    policies: PolicyCache
    enforcer: PolicyEnforcer
    approvals: ApprovalsService
    rules: RuleStore
    classifier: ClassifierHandle
    scanner: ScanService
    mcp: McpService
    pepper: bytes
    master_key: bytes
    jwt_secret: str
    session_secret: str
    judge_factory: JudgeFactory | None = None


async def init_state(app: FastAPI, settings: Settings) -> AppState:
    http = httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=5.0), follow_redirects=False,
                             transport=SafeTransport(allow_private=settings.private_hosts))
    redis = aioredis.from_url(settings.redis_url, decode_responses=False)
    engine = create_engine(settings.database_url)
    emitter = Emitter(redis, Spool(settings.spool_dir))
    policies = PolicyCache()
    enforcer = PolicyEnforcer(engine=engine, redis=redis, emitter=emitter, cache=policies)
    approvals = ApprovalsService(engine=engine, redis=redis, emitter=emitter, http=http,
                                 ttl_seconds=settings.approval_ttl_seconds,
                                 allowance_seconds=settings.approval_allowance_seconds,
                                 dashboard_url=settings.dashboard_url, allow_private=settings.private_hosts)
    enforcer.approvals = approvals
    rules = RuleStore(refresh_seconds=settings.rules_refresh_seconds)
    classifier = load_classifier(settings.classifier, settings.classifier_dir)
    upstream_client = UpstreamClient(http, allow_private=settings.private_hosts, max_bytes=settings.upstream_max_bytes)
    scanner = ScanService(engine=engine, redis=redis, emitter=emitter, rules=rules, classifier=classifier,
                          upstream=upstream_client, master_key=settings.master_key_bytes,
                          judge_timeout=settings.judge_timeout_seconds)
    mcp = McpService(engine=engine, emitter=emitter, scanner=scanner, http_provider=lambda: upstream_client.http, master_key=settings.master_key_bytes,
                     allow_private=settings.private_hosts)
    state = AppState(
        settings=settings,
        engine=engine,
        redis=redis,
        emitter=emitter,
        budgets=BudgetTracker(redis, default_rpm=settings.default_rpm),
        policies=policies,
        enforcer=enforcer,
        approvals=approvals,
        rules=rules,
        classifier=classifier,
        scanner=scanner,
        mcp=mcp,
        http=http,
        upstream=upstream_client,
        pepper=settings.pepper_bytes,
        master_key=settings.master_key_bytes,
        jwt_secret=settings.jwt_secret_value,
        session_secret=settings.session_secret_value,
        judge_factory=enforcer.judge_factory(),
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
