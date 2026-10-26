"""Metrics (Prometheus), tracing (OpenTelemetry) and the security headers the API always sends.

Metrics live in one module-level registry so every component can record without being handed an object.
Tracing is optional: with no exporter configured the spans are no-ops. The AgentShield `trace_id` is set
as a span attribute and each audit event stores `otel_span_id`, so a log line and a span can be joined.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from fastapi import FastAPI, Request
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .settings import Settings

log = logging.getLogger("agentshield.observability")

REGISTRY = CollectorRegistry()
LATENCY_BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)

DECISIONS = Counter("agentshield_decisions_total", "Decisions recorded in the audit log", ["decision", "module"],
                    registry=REGISTRY)
SCAN_LATENCY = Histogram("agentshield_scan_latency_seconds", "Injection scan time by layer", ["layer"],
                         buckets=LATENCY_BUCKETS, registry=REGISTRY)
POLICY_EVAL = Histogram("agentshield_policy_eval_seconds", "Policy evaluation time", buckets=LATENCY_BUCKETS,
                        registry=REGISTRY)
AUDIT_LAG = Gauge("agentshield_audit_lag_seconds", "Age of the newest event the audit worker wrote, when it wrote it",
                  registry=REGISTRY)
APPROVALS_PENDING = Gauge("agentshield_approvals_pending", "Approvals waiting for a human", registry=REGISTRY)
STREAM_PENDING = Gauge("agentshield_stream_pending", "Audit events published but not yet written", registry=REGISTRY)

_provider: TracerProvider | None = None


# ── tracing ─────────────────────────────────────────────────────────────────────────────────────────
def set_tracer_provider(provider: TracerProvider | None) -> None:
    """Use this provider for AgentShield's own spans (tests pass an in-memory one)."""
    global _provider
    _provider = provider


def tracer() -> trace.Tracer:
    return _provider.get_tracer("agentshield") if _provider is not None else trace.get_tracer("agentshield")


@contextmanager
def span(name: str, **attrs: Any) -> Iterator[trace.Span]:
    with tracer().start_as_current_span(name) as sp:
        for k, v in attrs.items():
            sp.set_attribute(k, v)
        yield sp


def link_trace(trace_id: str) -> None:
    """Attach the AgentShield trace id to the current request span."""
    sp = trace.get_current_span()
    if sp.get_span_context().is_valid:
        sp.set_attribute("agentshield.trace_id", trace_id)


def current_span_ref() -> str | None:
    ctx = trace.get_current_span().get_span_context()
    return f"{ctx.trace_id:032x}-{ctx.span_id:016x}" if ctx.is_valid else None


@contextmanager
def timed(observe: Any) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        observe(time.perf_counter() - start)


def setup_observability(app: FastAPI, settings: Settings, tracer_provider: TracerProvider | None = None) -> None:
    """Instrument the app. Called once from `create_app`."""
    if not settings.otel_enabled:
        return
    provider = tracer_provider
    if provider is None and settings.otlp_endpoint:
        provider = _otlp_provider(settings)
    if provider is not None:
        set_tracer_provider(provider)
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app, tracer_provider=provider, excluded_urls="healthz,readyz,metrics")
    except Exception:                                                  # noqa: BLE001
        log.exception("could not instrument FastAPI")


def instrument_clients(state: Any, provider: TracerProvider | None) -> None:
    """Spans for outgoing HTTP, SQL and Redis calls (run from the lifespan, once the clients exist)."""
    if not state.settings.otel_enabled:
        return
    for name, fn in (("httpx", _instrument_httpx), ("sqlalchemy", _instrument_sqlalchemy), ("redis", _instrument_redis)):
        try:
            fn(state, provider)
        except Exception:                                              # noqa: BLE001
            log.warning("could not instrument %s", name, exc_info=True)


def _instrument_httpx(state: Any, provider: TracerProvider | None) -> None:
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    HTTPXClientInstrumentor.instrument_client(state.http, tracer_provider=provider)


def _instrument_sqlalchemy(state: Any, provider: TracerProvider | None) -> None:
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
    SQLAlchemyInstrumentor().instrument(engine=state.engine.sync_engine, tracer_provider=provider, enable_commenter=False)


def _instrument_redis(state: Any, provider: TracerProvider | None) -> None:
    from opentelemetry.instrumentation.redis import RedisInstrumentor
    RedisInstrumentor().instrument_client(state.redis, tracer_provider=provider)


def _otlp_provider(settings: Settings) -> TracerProvider | None:
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        log.warning("AGENTSHIELD_OTLP_ENDPOINT is set but opentelemetry-exporter-otlp-proto-http is not installed")
        return None
    provider = TracerProvider(resource=Resource.create({"service.name": "agentshield"}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.otlp_endpoint)))
    return provider


# ── /metrics access ─────────────────────────────────────────────────────────────────────────────────
def is_internal(host: str | None, extra_cidrs: str = "") -> bool:
    """Private, loopback and link-local addresses, plus any configured CIDRs. Unparsable means no."""
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return True
    for cidr in (c.strip() for c in extra_cidrs.split(",") if c.strip()):
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def client_is_internal(request: Request, settings: Settings) -> bool:
    # The socket peer, never X-Forwarded-For: a header is something the caller controls.
    return is_internal(request.client.host if request.client else None, settings.metrics_allowed_cidrs)


# ── security headers ────────────────────────────────────────────────────────────────────────────────
class SecurityHeadersMiddleware:
    """Adds the always-on response headers (api spec §A.6, API8). Never overrides a header a route set."""

    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        self.app, self.hsts = app, hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope["path"]
        docs = path.startswith(("/docs", "/redoc"))

        async def wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = {k.lower() for k, _ in message["headers"]}
                add: dict[bytes, bytes] = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"permissions-policy": b"geolocation=(), microphone=(), camera=()",
                    b"cross-origin-resource-policy": b"same-site",
                }
                if not docs:
                    add[b"content-security-policy"] = b"default-src 'none'; frame-ancestors 'none'"
                if path.startswith(("/v1/admin", "/v1/auth", "/v1/token", "/v1/signup")):
                    add[b"cache-control"] = b"no-store"
                if self.hsts:
                    add[b"strict-transport-security"] = b"max-age=63072000; includeSubDomains"
                message["headers"] = [*message["headers"], *((k, v) for k, v in add.items() if k not in headers)]
            await send(message)

        await self.app(scope, receive, wrapped)
