"""Human approvals: queue, webhook, expiry, long-poll and the 15-minute allowance (arch §2.1).

An `ask` decision creates a pending approval. A reviewer (analyst or admin, never an agent) approves or
denies it. Approval grants the *exact* call (session + tool + argument hash) an allowance for 15 minutes;
a pending approval that nobody answers within 5 minutes expires and counts as a denial.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from ..audit.emitter import Emitter
from ..audit.redact import redact
from ..contracts.decision import Decision
from ..contracts.errors import ApiError
from ..contracts.events import AuditEvent, EventType
from ..contracts.ids import new_trace_id
from ..db.tenant_tx import system_tx, tenant_tx
from ..proxy.sessions import SessionRef
from ..tenants.context import TenantContext
from ..tenants.registry import etag
from ..tenants.urls import UnsafeURL, avalidate_outbound_url
from .evaluator import Evaluation
from .session_state import grant_allowance

log = logging.getLogger("agentshield.approvals")
Row = dict[str, Any]
_COLS = ("a.id, ag.slug as agent_slug, a.session_id, a.trace_id, a.tool, a.args_hash, a.args_redacted, a.rule_id, "
         "a.status, a.decided_by, u.email as decided_by_email, a.decided_at, a.note, a.expires_at, a.created_at")
_FROM = "approvals a join agents ag on ag.id = a.agent_id left join users u on u.id = a.decided_by"


def approval_etag(row: Row) -> str:
    return etag(row["id"], row["status"], row["decided_at"].isoformat() if row["decided_at"] else "")


def webhook_body(row: Row, dashboard_url: str) -> dict[str, Any]:
    """What goes to the webhook: raw tool + redacted arguments only, never model-written prose."""
    link = f"{dashboard_url.rstrip('/')}/approvals/{row['id']}"
    return {
        "text": f"AgentShield: agent {row['agent_slug']} wants to run {row['tool']} and needs approval "
                f"(rule {row['rule_id']}). Review: {link}",
        "approval_id": str(row["id"]), "agent": row["agent_slug"], "tool": row["tool"],
        "arguments_redacted": row["args_redacted"], "rule_id": row["rule_id"],
        "expires_at": row["expires_at"].isoformat(), "dashboard_url": link,
    }


class ApprovalsService:
    def __init__(self, *, engine: AsyncEngine, redis: Any, emitter: Emitter, http: httpx.AsyncClient,
                 ttl_seconds: int = 300, allowance_seconds: int = 900, dashboard_url: str = "http://localhost:5173",
                 allow_private: set[str] | None = None) -> None:
        self.engine, self.redis, self.emitter, self.http = engine, redis, emitter, http
        self.ttl, self.allowance = ttl_seconds, allowance_seconds
        self.dashboard_url = dashboard_url
        self.allow_private = allow_private or set()
        self._tasks: set[asyncio.Task[None]] = set()

    # ── creating ────────────────────────────────────────────────────────────────────────────────
    async def request(self, ctx: TenantContext, agent: dict[str, Any], session: SessionRef, tool: str,
                      arguments: Any, evaluation: Evaluation, trace_id: str) -> str | None:
        args = arguments if isinstance(arguments, dict) else {"_raw": str(arguments)[:2000]}
        redacted = redact(args, pii=False).value        # reviewers must see recipients; secrets stay masked
        async with tenant_tx(self.engine, ctx.tenant_id) as conn:
            existing = (await conn.execute(text(
                "select id from approvals where session_id = :s and tool = :t and args_hash = :h and status = 'pending' "
                "and expires_at > now() order by id desc limit 1"),
                {"s": session.id, "t": tool, "h": evaluation.args_hash})).scalar_one_or_none()
            if existing is not None:
                return str(existing)                   # the agent retried while a reviewer is still deciding
            new_id = (await conn.execute(text(
                "insert into approvals (tenant_id, agent_id, session_id, trace_id, tool, args_hash, args_redacted, "
                "rule_id, expires_at) values (:t, :a, :s, :tr, :tool, :h, cast(:r as jsonb), :rule, "
                "now() + make_interval(secs => :ttl)) returning id"),
                {"t": ctx.tenant_id, "a": agent["id"], "s": session.id, "tr": trace_id, "tool": tool,
                 "h": evaluation.args_hash, "r": json.dumps(redacted), "rule": evaluation.rule_id,
                 "ttl": self.ttl})).scalar_one()
            row = await self._get(conn, new_id)
            webhook = (await conn.execute(text("select settings->>'webhook_url' from tenants"))).scalar_one_or_none()
        await self.emitter.emit(
            AuditEvent(tenant_id=str(ctx.tenant_id), agent_slug=agent["slug"], session_id=str(session.id),
                       end_user=session.end_user, trace_id=trace_id, module="approval", type=EventType.approval_requested,
                       decision=Decision.ask, rule_id=evaluation.rule_id, reason=evaluation.reason, severity="medium",
                       summary=f"approval requested for {tool}"),
            {"approval_id": str(new_id), "tool": tool, "arguments": redacted, "expires_at": row["expires_at"].isoformat()})
        if webhook:
            task = asyncio.create_task(self._notify(ctx.tenant_id, row, webhook))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        return str(new_id)

    async def _notify(self, tenant_id: UUID, row: Row, url: str) -> None:
        error: str | None = None
        for attempt in range(3):
            try:
                await avalidate_outbound_url(url, allow_private=self.allow_private)
                resp = await self.http.post(url, json=webhook_body(row, self.dashboard_url), timeout=5.0)
                if resp.status_code < 300:
                    return
                error = f"HTTP {resp.status_code}"
            except UnsafeURL as exc:
                error = f"webhook URL rejected: {exc}"
                break
            except Exception as exc:                                      # noqa: BLE001
                error = type(exc).__name__
            await asyncio.sleep(0.2 * (attempt + 1))
        await self.emitter.emit(
            AuditEvent(tenant_id=str(tenant_id), agent_slug=row["agent_slug"], session_id=str(row["session_id"]),
                       trace_id=row["trace_id"], module="approval", type=EventType.approval_notify_failed,
                       severity="medium", summary=f"could not notify the webhook: {error}"),
            {"approval_id": str(row["id"]), "error": error})

    async def drain_notifications(self) -> None:
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    # ── reading ─────────────────────────────────────────────────────────────────────────────────
    async def _get(self, conn: AsyncConnection, approval_id: UUID | str) -> Row:
        row = (await conn.execute(text(f"select {_COLS} from {_FROM} where a.id = :i"), {"i": approval_id})).mappings().first()
        if row is None:
            raise ApiError("not_found", "Approval not found")
        return dict(row)

    async def get(self, tenant_id: UUID, approval_id: UUID | str, *, agent_slug: str | None = None) -> Row:
        await self._expire_one(tenant_id, approval_id)
        async with tenant_tx(self.engine, tenant_id) as conn:
            row = await self._get(conn, approval_id)
        if agent_slug is not None and row["agent_slug"] != agent_slug:
            raise ApiError("not_found", "Approval not found")           # agents only see their own requests
        return row

    async def list(self, tenant_id: UUID, *, status: str | None, limit: int, cursor: UUID | None) -> tuple[list[Row], str | None]:
        await self.expire_due(tenant_id=tenant_id)
        async with tenant_tx(self.engine, tenant_id) as conn:
            rows = (await conn.execute(text(
                f"select {_COLS} from {_FROM} where (cast(:st as text) is null or a.status = :st) "
                "and (cast(:c as uuid) is null or a.id < cast(:c as uuid)) order by a.id desc limit :n"),
                {"st": status, "c": cursor, "n": limit + 1})).mappings().all()
        items = [dict(r) for r in rows]
        if len(items) > limit:
            items = items[:limit]
            from ..tenants.registry import encode_cursor
            return items, encode_cursor(str(items[-1]["id"]))
        return items, None

    async def prior_denial(self, ctx: TenantContext, session: SessionRef, tool: str, args_hash: str) -> Row | None:
        """A reviewer already denied this exact call in this session within the allowance window."""
        async with tenant_tx(self.engine, ctx.tenant_id) as conn:
            row = (await conn.execute(text(
                f"select {_COLS} from {_FROM} where a.session_id = :s and a.tool = :t and a.args_hash = :h "
                "and a.status = 'denied' and a.decided_at > now() - make_interval(secs => :w) "
                "order by a.id desc limit 1"), {"s": session.id, "t": tool, "h": args_hash, "w": self.allowance})
            ).mappings().first()
        return dict(row) if row else None

    # ── deciding ────────────────────────────────────────────────────────────────────────────────
    async def decide(self, ctx: TenantContext, approval_id: UUID, approve: bool, note: str | None,
                     if_match: str | None) -> Row:
        if ctx.actor != "user" or not ctx.has_role("analyst"):
            raise ApiError("forbidden", "Only analysts and admins can decide approvals")
        await self._expire_one(ctx.tenant_id, approval_id)
        async with tenant_tx(self.engine, ctx.tenant_id) as conn:
            current = await self._get(conn, approval_id)
            if current["status"] != "pending":
                raise ApiError("conflict", f"This approval was already {current['status']}"
                                           + (f" by {current['decided_by_email']}" if current["decided_by_email"] else ""))
            if not if_match:
                raise ApiError("precondition_required", "This change requires an If-Match header with the approval ETag")
            if if_match.strip() not in {approval_etag(current), approval_etag(current).removeprefix("W/")} and if_match.strip() != "*":
                raise ApiError("precondition_failed", "The approval changed since you loaded it")
            res = await conn.execute(text(
                "update approvals set status = :s, decided_by = :u, decided_at = now(), note = :n "
                "where id = :i and status = 'pending'"),
                {"s": "approved" if approve else "denied", "u": ctx.actor_id, "n": (note or None), "i": approval_id})
            if res.rowcount == 0:
                raise ApiError("conflict", "This approval was decided by someone else a moment ago")
            row = await self._get(conn, approval_id)
            agent_id, session_id = (await conn.execute(text("select agent_id, session_id from approvals where id = :i"),
                                                       {"i": approval_id})).one()
        if approve:
            await grant_allowance(self.redis, ctx.tenant_id, session_id, row["tool"], row["args_hash"], self.allowance)
        await self._announce(ctx.tenant_id, row, by=ctx.actor_id)
        _ = agent_id
        return row

    async def _announce(self, tenant_id: UUID, row: Row, *, by: UUID | None) -> None:
        status = row["status"]
        await self.emitter.emit(
            AuditEvent(tenant_id=str(tenant_id), agent_slug=row["agent_slug"], session_id=str(row["session_id"]),
                       trace_id=row["trace_id"], module="approval", type=EventType.approval_decided,
                       decision=Decision.allow if status == "approved" else Decision.block, rule_id=row["rule_id"],
                       reason=f"approval {status}" + (f": {row['note']}" if row.get("note") else ""),
                       severity="medium" if status != "approved" else "info", summary=f"approval {status} for {row['tool']}"),
            {"approval_id": str(row["id"]), "status": status, "tool": row["tool"], "decided_by": str(by) if by else None,
             "note": row.get("note")})
        try:
            await self.redis.publish(f"approval:{row['id']}", status)
        except Exception:                                                 # noqa: BLE001
            log.warning("could not publish approval decision")

    # ── expiry ──────────────────────────────────────────────────────────────────────────────────
    async def _expire_one(self, tenant_id: UUID, approval_id: UUID | str) -> None:
        async with tenant_tx(self.engine, tenant_id) as conn:
            res = await conn.execute(text(
                "update approvals set status = 'expired', decided_at = now() where id = :i and status = 'pending' "
                "and expires_at < now()"), {"i": approval_id})
            if res.rowcount:
                await self._announce(tenant_id, await self._get(conn, approval_id), by=None)

    async def expire_due(self, *, tenant_id: UUID | None = None, now: datetime | None = None) -> int:
        """Expire pending approvals past their deadline (a non-answer is a denial). Safe on several instances."""
        if tenant_id is None:
            async with system_tx(self.engine) as conn:
                tenants = [r[0] for r in (await conn.execute(
                    text("select tenant_id from private.tenants_with_due_approvals(:now)"),
                    {"now": now or datetime.now(UTC)})).all()]
        else:
            tenants = [tenant_id]
        total = 0
        for t in tenants:
            async with tenant_tx(self.engine, t) as conn:
                rows = (await conn.execute(text(
                    "update approvals set status = 'expired', decided_at = :now where id in ("
                    " select id from approvals where status = 'pending' and expires_at < :now "
                    " order by expires_at limit 100 for update skip locked) returning id"),
                    {"now": now or datetime.now(UTC)})).all()
                expired = [await self._get(conn, r[0]) for r in rows]
            for row in expired:
                await self._announce(t, row, by=None)
            total += len(expired)
        return total

    async def sweep_forever(self, interval: float) -> None:
        while True:
            try:
                await self.expire_due()
            except asyncio.CancelledError:
                raise
            except Exception:                                             # noqa: BLE001
                log.exception("approval sweep failed")
            await asyncio.sleep(interval)

    # ── long-poll ───────────────────────────────────────────────────────────────────────────────
    async def wait(self, tenant_id: UUID, approval_id: UUID | str, seconds: float) -> Row:
        """Return the approval as soon as it is decided, or after `seconds` (still pending)."""
        deadline = time.monotonic() + seconds
        pubsub = self.redis.pubsub()
        try:
            await pubsub.subscribe(f"approval:{approval_id}")
            while True:
                row = await self.get(tenant_id, approval_id)
                remaining = deadline - time.monotonic()
                if row["status"] != "pending" or remaining <= 0:
                    return row
                await pubsub.get_message(ignore_subscribe_messages=True, timeout=min(remaining, 2.0))
        finally:
            try:
                await pubsub.unsubscribe()
                await pubsub.aclose()
            except Exception:                                             # noqa: BLE001
                log.debug("pubsub cleanup failed", exc_info=True)


_ = (timedelta, new_trace_id)
