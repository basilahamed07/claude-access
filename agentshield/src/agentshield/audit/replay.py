"""Replay recorded tool calls against a policy version (also powers the policy simulator).

Each `tool.requested` event is paired with the `policy.decision` that followed it in the same trace and
re-evaluated with the chosen policy, using the session risk and human approvals recorded at the time.
Arguments come from the audit payload, which is redacted before storage, so replay is exact for rules
over domains, numbers and tool names and approximate for rules over redacted text. Model text is not
re-generated: it is shown as recorded.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from ..contracts.admin import ReplayResult, ReplayStep, SimulateResult
from ..contracts.decision import Decision, EffectTag
from ..contracts.errors import ApiError
from ..db.tenant_tx import tenant_tx
from ..policy import store
from ..policy.cache import PolicyCache
from ..policy.evaluator import SessionState, evaluate
from ..policy.loader import CompiledPolicy, parse_policy

MAX_CALLS = 20_000
MAX_DIFFS = 200


@dataclass
class RecordedCall:
    seq: int
    ts: datetime
    trace_id: str
    session_id: UUID | None
    tool: str
    arguments: Any
    has_arguments: bool
    effect_tag: str | None
    decision: str | None
    rule_id: str | None
    risk: float
    approved: bool
    args_hash: str | None
    server: str | None = None


def _tool_from_summary(summary: str) -> str:
    return summary.rsplit(" requested", 1)[0] if " requested" in summary else "?"


async def load_calls(conn: AsyncConnection, tenant_id: UUID, *, session_ids: list[UUID] | None = None,
                     agent_slug: str | None = None, since: datetime | None = None) -> list[RecordedCall]:
    where = ["e.tenant_id = :t", "e.type in ('tool.requested', 'policy.decision')"]
    params: dict[str, Any] = {"t": tenant_id, "n": MAX_CALLS * 2}
    if session_ids is not None:
        where.append("e.session_id = any(:ids)")
        params["ids"] = session_ids
    if agent_slug:
        where.append("e.agent_slug = :agent")
        params["agent"] = agent_slug
    if since:
        where.append("e.ts >= :since")
        params["since"] = since
    rows = (await conn.execute(text(
        "select e.seq, e.ts, e.trace_id, e.session_id, e.type, e.decision, e.rule_id, e.summary, p.payload "
        "from audit_events e left join audit_payloads p on p.tenant_id = e.tenant_id and p.seq = e.seq and p.ts = e.ts "
        f"where {' and '.join(where)} order by e.seq limit :n"), params)).mappings().all()
    waiting: dict[str, deque[Any]] = defaultdict(deque)
    calls: list[RecordedCall] = []
    for r in rows:
        payload = r["payload"] if isinstance(r["payload"], dict) else None
        if r["type"] == "tool.requested":
            waiting[r["trace_id"]].append(r)
            continue
        if not waiting[r["trace_id"]]:
            continue
        req = waiting[r["trace_id"]].popleft()
        req_payload = req["payload"] if isinstance(req["payload"], dict) else None
        has_args = req_payload is not None and "arguments" in req_payload and not req_payload.get("_truncated")
        recorded = (payload or {}).get("would_have") or r["decision"]
        calls.append(RecordedCall(
            seq=int(req["seq"]), ts=req["ts"], trace_id=r["trace_id"], session_id=r["session_id"],
            tool=str((req_payload or payload or {}).get("tool") or _tool_from_summary(req["summary"])),
            arguments=(req_payload or {}).get("arguments"), has_arguments=has_args,
            effect_tag=(req_payload or payload or {}).get("effect_tag"), decision=recorded, rule_id=r["rule_id"],
            risk=float((payload or {}).get("risk_score") or 0.0),
            approved=bool((payload or {}).get("approved_by_human")),
            args_hash=(req_payload or payload or {}).get("args_hash"), server=(req_payload or payload or {}).get("server")))
    return calls[:MAX_CALLS]


def replay_calls(policy: CompiledPolicy, calls: list[RecordedCall]) -> list[ReplayStep]:
    steps: list[ReplayStep] = []
    for c in calls:
        step = ReplayStep(seq=c.seq, session_id=c.session_id, ts=c.ts, trace_id=c.trace_id, tool=c.tool, effect_tag=c.effect_tag,
                          recorded_decision=c.decision, recorded_rule=c.rule_id)
        if not c.has_arguments:
            step.skipped = "payload_purged_or_truncated"
            steps.append(step)
            continue
        tag = EffectTag(c.effect_tag) if c.effect_tag in {t.value for t in EffectTag} else None
        approved = frozenset({(c.tool, c.args_hash)}) if c.approved and c.args_hash else frozenset()
        ev = evaluate(policy, c.tool, c.arguments, SessionState(c.risk, approved), advised_tag=tag, server=c.server)
        step.replay_decision, step.replay_rule, step.replay_reason = ev.decision.value, ev.rule_id, ev.reason
        step.changed = step.replay_decision != c.decision
        steps.append(step)
    return steps


async def _policy_for(conn: AsyncConnection, cache: PolicyCache, agent: dict[str, Any],
                      version: int | None) -> tuple[CompiledPolicy, int | None]:
    use = version if version is not None else agent["active_policy_version"]
    if use is None:
        return parse_policy("version: 1\n"), None
    row = await store.get_version(conn, agent["id"], use)       # 404 for an unknown version
    _ = cache
    return parse_policy(row["yaml"]), use


async def replay_session(engine: AsyncEngine, cache: PolicyCache, tenant_id: UUID, session_id: UUID, *,
                         policy_version: int | None = None) -> ReplayResult:
    async with tenant_tx(engine, tenant_id) as conn:
        agent = (await conn.execute(text(
            "select a.id, a.active_policy_version from sessions s join agents a on a.id = s.agent_id where s.id = :s"),
            {"s": session_id})).mappings().first()
        if agent is None:
            raise ApiError("not_found", "Session not found")
        policy, used = await _policy_for(conn, cache, dict(agent), policy_version)
        calls = await load_calls(conn, tenant_id, session_ids=[session_id])
    steps = replay_calls(policy, calls)
    skipped = sum(1 for s in steps if s.skipped)
    return ReplayResult(session_id=session_id, policy_version=used, compared=len(steps) - skipped, skipped=skipped,
                        changed=sum(1 for s in steps if s.changed), steps=steps)


async def simulate(engine: AsyncEngine, cache: PolicyCache, tenant_id: UUID, agent_slug: str, version: int, *,
                   session_ids: list[UUID] | None, since: datetime | None) -> SimulateResult:
    async with tenant_tx(engine, tenant_id) as conn:
        agent = (await conn.execute(text("select id, active_policy_version from agents where slug = :s"),
                                    {"s": agent_slug})).mappings().first()
        if agent is None:
            raise ApiError("not_found", "Agent not found")
        policy, _ = await _policy_for(conn, cache, dict(agent), version)
        if session_ids is not None:       # only sessions of this agent count; foreign or unknown ids are ignored
            own = (await conn.execute(text("select id from sessions where agent_id = :a and id = any(:ids)"),
                                      {"a": agent["id"], "ids": session_ids})).scalars().all()
            session_ids = list(own)
        calls = await load_calls(conn, tenant_id, session_ids=session_ids, agent_slug=agent_slug, since=since)
    steps = replay_calls(policy, calls)
    changed = [s for s in steps if s.changed]
    sessions = len({c.session_id for c in calls})

    def moved(to: Decision) -> int:
        return sum(1 for s in changed if s.replay_decision == to.value)

    return SimulateResult(
        version=version, sessions=sessions, compared=sum(1 for s in steps if not s.skipped),
        skipped=sum(1 for s in steps if s.skipped), changed=len(changed), newly_blocked=moved(Decision.block),
        newly_allowed=moved(Decision.allow), newly_asked=moved(Decision.ask), diffs=changed[:MAX_DIFFS],
        truncated=len(changed) > MAX_DIFFS)
