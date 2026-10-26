"""Reading the audit log (keyset pagination on (ts, seq), newest first)."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from ..contracts.errors import ApiError
from .chain import iso


@dataclass
class EventFilter:
    agent: str | None = None
    session: UUID | None = None
    trace: str | None = None
    user: str | None = None
    module: str | None = None
    type: str | None = None
    decision: str | None = None
    severity: str | None = None
    tool: str | None = None
    since: datetime | None = None
    until: datetime | None = None


def encode_cursor(ts: datetime, seq: int) -> str:
    return base64.urlsafe_b64encode(f"{iso(ts)}|{seq}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> tuple[datetime, int] | None:
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        ts, seq = raw.split("|")
        return datetime.fromisoformat(ts), int(seq)
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ApiError("validation_failed", "Invalid cursor") from exc


_COLS = ("e.seq, e.ts, e.id, e.trace_id, e.session_id, e.agent_slug, e.end_user, e.module, e.type, e.decision, "
         "e.rule_id, e.reason, e.severity, e.summary, e.payload_truncated, encode(e.hash, 'hex') as hash")


async def list_events(conn: AsyncConnection, tenant_id: UUID, f: EventFilter, limit: int, cursor: str | None,
                      *, include_payload: bool = False) -> tuple[list[dict[str, Any]], str | None]:
    where = ["e.tenant_id = :t"]
    params: dict[str, Any] = {"t": tenant_id, "n": limit + 1}
    for col, val in (("agent_slug", f.agent), ("session_id", f.session), ("trace_id", f.trace), ("end_user", f.user),
                     ("module", f.module), ("type", f.type), ("decision", f.decision), ("severity", f.severity)):
        if val is not None:
            where.append(f"e.{col} = :{col}")
            params[col] = val
    if f.tool:
        where.append("exists (select 1 from audit_payloads p where p.tenant_id = e.tenant_id and p.seq = e.seq "
                     "and p.ts = e.ts and p.payload->>'tool' = :tool)")
        params["tool"] = f.tool
    if f.since:
        where.append("e.ts >= :since")
        params["since"] = f.since
    if f.until:
        where.append("e.ts < :until")
        params["until"] = f.until
    cur = decode_cursor(cursor)
    if cur:
        where.append("(e.ts, e.seq) < (:cts, :cseq)")
        params["cts"], params["cseq"] = cur
    payload_col = ", p.payload as payload" if include_payload else ""
    payload_join = ("left join audit_payloads p on p.tenant_id = e.tenant_id and p.seq = e.seq and p.ts = e.ts"
                    if include_payload else "")
    avail = ", exists (select 1 from audit_payloads q where q.tenant_id = e.tenant_id and q.seq = e.seq and q.ts = e.ts) as payload_available"
    rows = (await conn.execute(text(
        f"select {_COLS}{avail}{payload_col} from audit_events e {payload_join} where {' and '.join(where)} "
        "order by e.ts desc, e.seq desc limit :n"), params)).mappings().all()
    items = [dict(r) for r in rows]
    nxt = None
    if len(items) > limit:
        items = items[:limit]
        nxt = encode_cursor(items[-1]["ts"], int(items[-1]["seq"]))
    return items, nxt


# ── sessions, timeline, alerts, stats (B17) ──────────────────────────────────────────────────────
_SESSION_SQL = (
    "select s.id, a.slug as agent_slug, s.end_user, s.user_request, s.risk_score, s.started_at, s.last_seen_at, "
    "(select count(*) from audit_events e where e.tenant_id = s.tenant_id and e.session_id = s.id "
    "  and e.type = 'tool.requested') as calls, "
    "(select count(*) from audit_events e where e.tenant_id = s.tenant_id and e.session_id = s.id "
    "  and e.type = 'policy.decision' and e.decision = 'block') as blocked "
    "from sessions s join agents a on a.id = s.agent_id where s.tenant_id = :t")


def _session_cursor(ts: datetime, sid: UUID) -> str:
    return base64.urlsafe_b64encode(f"{iso(ts)}|{sid}".encode()).decode().rstrip("=")


def _decode_session_cursor(cursor: str | None) -> tuple[datetime, UUID] | None:
    if not cursor:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        ts, sid = raw.split("|")
        return datetime.fromisoformat(ts), UUID(sid)
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise ApiError("validation_failed", "Invalid cursor") from exc


async def list_sessions(conn: AsyncConnection, tenant_id: UUID, *, agent: str | None, user: str | None,
                        min_risk: float | None, limit: int, cursor: str | None) -> tuple[list[dict[str, Any]], str | None]:
    sql, params = _SESSION_SQL, {"t": tenant_id, "n": limit + 1}
    if agent:
        sql += " and a.slug = :agent"
        params["agent"] = agent
    if user:
        sql += " and s.end_user = :user"
        params["user"] = user
    if min_risk is not None:
        sql += " and s.risk_score >= :risk"
        params["risk"] = min_risk
    cur = _decode_session_cursor(cursor)
    if cur:
        sql += " and (s.last_seen_at, s.id) < (:cts, :cid)"
        params["cts"], params["cid"] = cur
    rows = (await conn.execute(text(sql + " order by s.last_seen_at desc, s.id desc limit :n"), params)).mappings().all()
    items = [dict(r) for r in rows]
    nxt = None
    if len(items) > limit:
        items = items[:limit]
        nxt = _session_cursor(items[-1]["last_seen_at"], items[-1]["id"])
    return items, nxt


async def get_session(conn: AsyncConnection, tenant_id: UUID, session_id: UUID) -> dict[str, Any]:
    row = (await conn.execute(text(_SESSION_SQL + " and s.id = :s"), {"t": tenant_id, "s": session_id})).mappings().first()
    if row is None:
        raise ApiError("not_found", "Session not found")
    return dict(row)


MAX_TIMELINE_EVENTS = 5000


async def session_events(conn: AsyncConnection, tenant_id: UUID, session_id: UUID, *, include_payload: bool,
                         limit: int = MAX_TIMELINE_EVENTS) -> list[dict[str, Any]]:
    """Every event of one session in chain order (oldest first)."""
    payload_col = ", p.payload as payload" if include_payload else ""
    join = "left join audit_payloads p on p.tenant_id = e.tenant_id and p.seq = e.seq and p.ts = e.ts" if include_payload else ""
    avail = (", exists (select 1 from audit_payloads q where q.tenant_id = e.tenant_id and q.seq = e.seq "
             "and q.ts = e.ts) as payload_available")
    rows = (await conn.execute(text(
        f"select {_COLS}{avail}{payload_col} from audit_events e {join} "
        "where e.tenant_id = :t and e.session_id = :s order by e.seq limit :n"),
        {"t": tenant_id, "s": session_id, "n": limit})).mappings().all()
    return [dict(r) for r in rows]


ALERT_KINDS: dict[str, str] = {
    "blocked_call": "e.type = 'policy.decision' and e.decision = 'block'",
    "malicious_content": "e.type = 'content.scanned' and e.severity in ('high', 'critical')",
    "approval_expired": "e.type = 'approval.decided' and e.reason like 'approval expired%'",
    "budget_exceeded": "e.type = 'budget.exceeded'",
    "audit_gap": "e.type = 'audit.gap'",
}
_ALERT_CASE = "case " + " ".join(f"when {cond} then '{kind}'" for kind, cond in ALERT_KINDS.items()) + " end"


async def list_alerts(conn: AsyncConnection, tenant_id: UUID, *, since: datetime, kind: str | None, limit: int,
                      cursor: str | None) -> tuple[list[dict[str, Any]], str | None]:
    conds = [ALERT_KINDS[kind]] if kind else list(ALERT_KINDS.values())
    where = ["e.tenant_id = :t", "e.ts >= :since", "(" + " or ".join(f"({c})" for c in conds) + ")"]
    params: dict[str, Any] = {"t": tenant_id, "since": since, "n": limit + 1}
    cur = decode_cursor(cursor)
    if cur:
        where.append("(e.ts, e.seq) < (:cts, :cseq)")
        params["cts"], params["cseq"] = cur
    rows = (await conn.execute(text(
        f"select {_ALERT_CASE} as kind, e.ts, e.seq, e.severity, e.summary, e.agent_slug, e.session_id, e.trace_id, "
        f"e.rule_id from audit_events e where {' and '.join(where)} order by e.ts desc, e.seq desc limit :n"),
        params)).mappings().all()
    items = [dict(r) for r in rows]
    nxt = None
    if len(items) > limit:
        items = items[:limit]
        nxt = encode_cursor(items[-1]["ts"], int(items[-1]["seq"]))
    return items, nxt


async def overview(conn: AsyncConnection, tenant_id: UUID, window: str, now: datetime) -> dict[str, Any]:
    from datetime import timedelta
    span = timedelta(hours=24) if window == "24h" else timedelta(days=7)
    since, bucket = now - span, ("hour" if window == "24h" else "day")
    p = {"t": tenant_id, "since": since}
    counts = (await conn.execute(text(
        "select count(*) filter (where type = 'tool.requested') as calls, "
        "count(*) filter (where type = 'policy.decision' and decision = 'allow') as allowed, "
        "count(*) filter (where type = 'policy.decision' and decision = 'block') as blocked, "
        "count(*) filter (where type = 'policy.decision' and decision = 'ask') as asked, "
        "count(*) filter (where type = 'content.scanned' and severity in ('high','critical')) as malicious_scans "
        "from audit_events where tenant_id = :t and ts >= :since"), p)).mappings().one()
    top_rules = (await conn.execute(text(
        "select rule_id as key, count(*) as count from audit_events where tenant_id = :t and ts >= :since "
        "and type = 'policy.decision' and decision = 'block' and rule_id is not null group by rule_id "
        "order by count desc, key limit 5"), p)).mappings().all()
    top_agents = (await conn.execute(text(
        "select agent_slug as key, count(*) as count from audit_events where tenant_id = :t and ts >= :since "
        "and type = 'policy.decision' and decision = 'block' and agent_slug is not null group by agent_slug "
        "order by count desc, key limit 5"), p)).mappings().all()
    series = (await conn.execute(text(
        f"select date_trunc('{bucket}', ts) as ts, "
        "count(*) filter (where decision = 'allow') as allowed, count(*) filter (where decision = 'block') as blocked, "
        "count(*) filter (where decision = 'ask') as asked from audit_events "
        "where tenant_id = :t and ts >= :since and type = 'policy.decision' group by 1 order by 1"), p)).mappings().all()
    sess = (await conn.execute(text(
        "select count(*) as active, count(*) filter (where risk_score >= 0.5) as risky from sessions "
        "where tenant_id = :t and last_seen_at >= :since"), p)).mappings().one()
    pending = (await conn.execute(text("select count(*) from approvals where tenant_id = :t and status = 'pending'"),
                                  {"t": tenant_id})).scalar_one()
    return {"window": window, **dict(counts), "approvals_pending": pending, "active_sessions": sess["active"],
            "risky_sessions": sess["risky"], "top_rules": [dict(r) for r in top_rules],
            "top_agents": [dict(r) for r in top_agents], "series": [dict(r) for r in series]}
