"""The one place a tool call becomes a decision (shared by the model proxy and POST /v1/check).

Order: load the agent's active policy -> read session risk and human approvals -> evaluate -> apply
monitor mode -> create an approval for `ask` -> audit. Anything that goes wrong follows the failure rule
decided once (arch §8.6): only `read` tools may proceed; every other tool is blocked.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncEngine

from ..audit.emitter import Emitter
from ..audit.events import make_event
from ..contracts.check import CheckResponse
from ..contracts.decision import FAIL_OPEN_TAGS, Decision, EffectTag
from ..contracts.events import EventType, Severity
from ..proxy.pipeline import JudgeFactory, ProxyCall
from ..proxy.sessions import SessionRef
from ..proxy.tools import ALLOW, Replace, ToolCall, ToolJudge, ToolJudgement
from ..tenants.context import TenantContext
from .cache import PolicyCache
from .evaluator import EVALUATOR_ERROR, Evaluation, SessionState, evaluate
from .session_state import get_risk, is_approved

log = logging.getLogger("agentshield.policy")
HIGH_IMPACT = {EffectTag.external, EffectTag.financial, EffectTag.destructive, EffectTag.execute}


class ApprovalService(Protocol):
    async def request(self, ctx: TenantContext, agent: dict[str, Any], session: SessionRef, tool: str,
                      arguments: Any, evaluation: Evaluation, trace_id: str) -> str | None: ...


@dataclass
class AgentInfo:
    id: UUID
    slug: str
    mode: str
    active_policy_version: int | None
    risk_tier: str = "medium"

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> AgentInfo:
        return cls(id=row.get("agent_id") or row["id"], slug=row["slug"], mode=row["mode"],
                   active_policy_version=row.get("active_policy_version"), risk_tier=row.get("risk_tier", "medium"))


def block_text(resp: CheckResponse) -> str:
    return f"Action blocked by AgentShield: {resp.reason} (rule {resp.rule_id}, trace {resp.trace_id})"


def ask_text(resp: CheckResponse) -> str:
    where = f"approval {resp.approval_id}, " if resp.approval_id else ""
    return f"Action needs human approval ({where}rule {resp.rule_id}); it was not executed."


class PolicyEnforcer:
    def __init__(self, *, engine: AsyncEngine, redis: Any, emitter: Emitter, cache: PolicyCache) -> None:
        self.engine, self.redis, self.emitter, self.cache = engine, redis, emitter, cache
        self.approvals: ApprovalService | None = None

    async def decide(self, ctx: TenantContext, agent: AgentInfo, session: SessionRef, tool: str,
                     arguments: Any, *, trace_id: str, source: str = "proxy", advised_tag: EffectTag | None = None,
                     budget_unavailable: bool = False) -> CheckResponse:
        risk = session.risk_score
        evaluation: Evaluation | None = None
        failure: str | None = None
        try:
            policy = await self.cache.get(self.engine, ctx.tenant_id, agent.id, agent.active_policy_version)
            risk = await get_risk(self.redis, ctx.tenant_id, session.id, session.risk_score)
            from .evaluator import args_hash
            digest = args_hash(arguments)
            approved = frozenset({(tool, digest)}) if await is_approved(self.redis, ctx.tenant_id, session.id, tool, digest) \
                else frozenset()
            evaluation = evaluate(policy, tool, arguments, SessionState(risk, approved), advised_tag=advised_tag)
        except Exception as exc:                                      # noqa: BLE001
            failure = type(exc).__name__
            log.exception("policy decision failed for tool %s", tool)
        if evaluation is None:
            tag = advised_tag or EffectTag.external
            fail_open = tag in FAIL_OPEN_TAGS
            decision = Decision.allow if fail_open else Decision.block
            rule = f"{EVALUATOR_ERROR}-fail-open" if fail_open else EVALUATOR_ERROR
            reason = (f"Policy could not be evaluated ({failure}); " +
                      ("read-only tool allowed" if fail_open else "action blocked"))
            evaluation = Evaluation(decision, rule, reason, (), tag, "", True)
        elif budget_unavailable and evaluation.decision is Decision.allow and evaluation.effect_tag not in FAIL_OPEN_TAGS:
            evaluation = Evaluation(Decision.block, "budget-service-unavailable",
                                    "The budget service is unavailable, so only read-only tools are allowed",
                                    evaluation.matched, evaluation.effect_tag, evaluation.args_hash, evaluation.args_valid)

        decision, would_have, mode = evaluation.decision, None, "enforce"
        reason = evaluation.reason
        if agent.mode == "monitor" and decision is not Decision.allow:
            would_have, decision, mode = decision, Decision.allow, "monitor"
            reason = f"[monitor mode: would have been {would_have.value}] {reason}"
        approval_id: str | None = None
        if decision is Decision.ask and self.approvals is not None:
            try:
                approval_id = await self.approvals.request(
                    ctx, {"id": agent.id, "slug": agent.slug}, session, tool, arguments, evaluation, trace_id)
            except Exception:                                         # noqa: BLE001
                log.exception("could not create approval")
                decision, reason = Decision.block, "Approval service unavailable; action blocked"
                evaluation = Evaluation(Decision.block, "approval-service-unavailable", reason, evaluation.matched,
                                        evaluation.effect_tag, evaluation.args_hash, evaluation.args_valid)
        resp = CheckResponse(decision=decision, reason=reason, rule_id=evaluation.rule_id, risk_score=min(max(risk, 0.0), 1.0),
                             approval_id=approval_id, mode=mode, would_have=would_have, trace_id=trace_id)
        await self._audit(ctx, session, tool, arguments, evaluation, resp, source, failure)
        return resp

    async def _audit(self, ctx: TenantContext, session: SessionRef, tool: str, arguments: Any, ev: Evaluation,
                     resp: CheckResponse, source: str, failure: str | None) -> None:
        base = {"tool": tool, "effect_tag": ev.effect_tag.value, "args_hash": ev.args_hash, "source": source}
        await self.emitter.emit(make_event(ctx, resp.trace_id, "gateway", EventType.tool_requested,
                                           f"{tool} requested ({ev.effect_tag.value})", session=session),
                                {**base, "arguments": arguments if arguments is not None else {}})
        severity: Severity = "info"
        if resp.decision is not Decision.allow or resp.would_have is not None:
            severity = "high" if ev.effect_tag in HIGH_IMPACT else "medium"
        await self.emitter.emit(
            make_event(ctx, resp.trace_id, "policy", EventType.policy_decision,
                       f"{tool} {resp.decision.value} by {resp.rule_id}", session=session, decision=resp.decision,
                       rule_id=resp.rule_id, reason=resp.reason, severity=severity),
            {**base, "matched": list(ev.matched), "risk_score": resp.risk_score, "mode": resp.mode,
             "would_have": resp.would_have.value if resp.would_have else None, "approval_id": resp.approval_id,
             "approved_by_human": ev.approved_by_human, "args_valid": ev.args_valid, "failure": failure})
        if failure:
            await self.emitter.emit(make_event(ctx, resp.trace_id, "policy", EventType.error,
                                               f"policy decision failed ({failure})", session=session, severity="high"),
                                    {"error": failure, "tool": tool})

    def judge_factory(self) -> JudgeFactory:
        def factory(pc: ProxyCall) -> ToolJudge:
            agent = AgentInfo.from_row(pc.agent)
            unavailable = bool(getattr(pc, "budget_unavailable", False))

            async def judge(call: ToolCall) -> ToolJudgement:
                args: Any = call.arguments if call.arguments is not None else call.raw_arguments
                resp = await self.decide(pc.ctx, agent, pc.session, call.name, args, trace_id=pc.trace_id,
                                         budget_unavailable=unavailable)
                if resp.decision is Decision.allow:
                    return ALLOW
                text = block_text(resp) if resp.decision is Decision.block else ask_text(resp)
                await self.emitter.emit(
                    make_event(pc.ctx, pc.trace_id, "gateway", EventType.tool_rewritten,
                               f"{call.name} replaced with a {resp.decision.value} notice", session=pc.session,
                               decision=resp.decision, rule_id=resp.rule_id, reason=resp.reason, severity="medium"),
                    {"tool": call.name, "text": text})
                return Replace(text)
            return judge
        return factory
