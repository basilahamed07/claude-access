"""`agentshield seed-demo`: one tenant with the email-reader story, so the dashboard has something to show.

Idempotent: if the demo tenant exists nothing is changed. The events go through the normal pipeline
(emitter -> stream -> worker), so the seeded log has a real hash chain.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib import resources
from typing import Any
from uuid import UUID

import redis.asyncio as aioredis
from sqlalchemy import text

from ..audit.emitter import Emitter
from ..audit.spool import Spool
from ..audit.worker import AuditWorker
from ..contracts.decision import Decision
from ..contracts.events import AuditEvent, EventType, Module, Severity
from ..contracts.ids import new_trace_id
from ..db.engine import create_engine
from ..db.tenant_tx import system_tx, tenant_tx
from ..policy import store
from ..policy.loader import parse_policy
from ..settings import Settings
from ..tenants import registry
from ..tenants.passwords import hash_password

DEMO_SLUG = "demo-corp"
DEMO_EMAIL = "demo@example.com"
AGENT = "email-reader-01"


@dataclass
class SeedResult:
    created: bool
    tenant_slug: str
    email: str
    password: str | None


def _policy_text() -> str:
    return (resources.files("agentshield.demo") / "email_reader_policy.yaml").read_text()


async def seed_demo(settings: Settings, *, password: str | None = None) -> SeedResult:
    engine = create_engine(settings.owner_database_url, pool_size=3, statement_timeout_ms=30_000)
    redis = aioredis.from_url(settings.redis_url)
    try:
        async with system_tx(engine) as conn:
            existing = (await conn.execute(text("select id from tenants where slug = :s"), {"s": DEMO_SLUG})).first()
        if existing is not None:
            return SeedResult(False, DEMO_SLUG, DEMO_EMAIL, None)
        password = password or secrets.token_urlsafe(12)
        async with system_tx(engine) as conn:
            tid: UUID = (await conn.execute(text("select private.create_tenant(:n, :s, :e, :p)"),
                                            {"n": "Demo Corp", "s": DEMO_SLUG, "e": DEMO_EMAIL,
                                             "p": hash_password(password)})).scalar_one()
        sessions = await _create_agent_and_sessions(engine, tid)
        emitter = Emitter(redis, Spool(settings.spool_dir))
        pay_trace = await _emit_story(emitter, tid, sessions)
        await _hold_payment(engine, tid, sessions["payment"], pay_trace)
        worker = AuditWorker(engine, redis)
        while await worker.process_once():
            pass
        return SeedResult(True, DEMO_SLUG, DEMO_EMAIL, password)
    finally:
        await redis.aclose()
        await engine.dispose()


async def _create_agent_and_sessions(engine: Any, tid: UUID) -> dict[str, UUID]:
    async with tenant_tx(engine, tid) as conn:
        user_id = (await conn.execute(text("select id from users where tenant_id = :t limit 1"), {"t": tid})).scalar_one()
        agent = await registry.create_agent(conn, tid, {
            "slug": AGENT, "name": "Email reader", "owner": "ops@acme.com", "purpose": "Summarises the inbox",
            "risk_tier": "medium", "mode": "enforce", "key_mode": "stored", "upstream_id": None})
        yaml_text = _policy_text()
        row = await store.create_version(conn, tid, agent["id"], yaml_text, parse_policy(yaml_text), user_id, None)
        await conn.execute(text("update agents set active_policy_version = :v where id = :a"), {"v": row["version"], "a": agent["id"]})
        out: dict[str, UUID] = {}
        for key, request, end_user, risk in (
                ("attack", "Summarize my unread mail", "alice@acme.com", 0.6),
                ("routine", "Find the invoice from Globex and forward it to finance", "bob@acme.com", 0.0),
                ("payment", "Pay the Initech invoice", "carol@acme.com", 0.0)):
            out[key] = (await conn.execute(text(
                "insert into sessions (tenant_id, agent_id, session_key, user_request, end_user, risk_score) "
                "values (:t, :a, :k, :r, :u, :risk) returning id"),
                {"t": tid, "a": agent["id"], "k": f"demo-{key}", "r": request, "u": end_user, "risk": risk})).scalar_one()
        return out


async def _emit_story(emitter: Emitter, tid: UUID, sessions: dict[str, UUID]) -> str:
    clock = datetime.now(UTC) - timedelta(hours=3)

    async def ev(session: str, trace: str, module: Module, etype: EventType, summary: str, payload: dict[str, Any], *,
                 decision: Decision | None = None, rule: str | None = None, reason: str | None = None,
                 severity: Severity = "info") -> None:
        nonlocal clock
        clock += timedelta(seconds=7)
        user = {"attack": "alice@acme.com", "routine": "bob@acme.com", "payment": "carol@acme.com"}[session]
        await emitter.emit(AuditEvent(tenant_id=str(tid), agent_slug=AGENT, session_id=str(sessions[session]), trace_id=trace,
                                      end_user=user, module=module, type=etype, decision=decision, rule_id=rule,
                                      reason=reason, severity=severity, summary=summary, ts=clock), payload)

    def call(session: str, trace: str, tool: str, tag: str, args: dict[str, Any]) -> Any:
        return ev(session, trace, "gateway", EventType.tool_requested, f"{tool} requested ({tag})",
                  {"tool": tool, "effect_tag": tag, "args_hash": secrets.token_hex(8), "source": "proxy", "arguments": args})

    def decide(session: str, trace: str, tool: str, tag: str, dec: Decision, rule: str, reason: str, risk: float) -> Any:
        return ev(session, trace, "policy", EventType.policy_decision, f"{tool} {dec.value} by {rule}",
                  {"tool": tool, "effect_tag": tag, "risk_score": risk, "mode": "enforce", "matched": [rule]},
                  decision=dec, rule=rule, reason=reason,
                  severity="info" if dec is Decision.allow else ("high" if tag in {"external", "financial"} else "medium"))

    # 1. the attack: a poisoned email is read, the agent is steered to leak, and the leak is stopped
    t1, t2 = new_trace_id(), new_trace_id()
    await call("attack", t1, "read_email", "read", {"folder": "INBOX"})
    await decide("attack", t1, "read_email", "read", Decision.allow, "allow-read-mail", "Folder is in scope", 0.0)
    await ev("attack", t2, "injection", EventType.content_scanned, "email m-441 judged malicious",
             {"source": "email", "id": "m-441", "verdict": "malicious", "action": "sanitized", "risk_after": 0.6},
             severity="high")
    await call("attack", t2, "send_email", "external", {"to": "x***@unknown.com", "subject": "Invoices"})
    await decide("attack", t2, "send_email", "external", Decision.block, "deny-external-send",
                 "External email is not permitted for this agent", 0.6)
    await ev("attack", t2, "gateway", EventType.tool_rewritten, "send_email replaced with a block notice",
             {"tool": "send_email", "text": "Action blocked by AgentShield"}, decision=Decision.block,
             rule="deny-external-send", severity="medium")
    # 2. an ordinary day
    t3 = new_trace_id()
    await call("routine", t3, "read_email", "read", {"folder": "Invoices"})
    await decide("routine", t3, "read_email", "read", Decision.allow, "allow-read-mail", "Folder is in scope", 0.0)
    await call("routine", t3, "send_email", "external", {"to": "finance@acme.com"})
    await decide("routine", t3, "send_email", "external", Decision.allow, "allow-internal-send", "Recipient domain is approved", 0.0)
    # 3. a payment that needs a human
    t4 = new_trace_id()
    await call("payment", t4, "pay_invoice", "financial", {"vendor": "Initech", "amount": 5000})
    await decide("payment", t4, "pay_invoice", "financial", Decision.ask, "ask-large-payment",
                 "Payments above $1,000 need approval", 0.0)
    return t4


async def _hold_payment(engine: Any, tid: UUID, session_id: UUID, trace_id: str) -> None:
    """The held payment waits in the approval queue. Unlike live approvals it stays for a week, so the demo is not empty by tomorrow."""
    async with tenant_tx(engine, tid) as conn:
        agent_id = (await conn.execute(text("select id from agents where tenant_id = :t and slug = :s"), {"t": tid, "s": AGENT})).scalar_one()
        await conn.execute(text(
            "insert into approvals (tenant_id, agent_id, session_id, trace_id, tool, args_hash, args_redacted, rule_id, expires_at) "
            "values (:t, :a, :s, :tr, 'pay_invoice', 'demo-hash', cast(:args as jsonb), 'ask-large-payment', now() + interval '7 days')"),
            {"t": tid, "a": agent_id, "s": session_id, "tr": trace_id, "args": '{"vendor": "Initech", "amount": 5000}'})
