"""Policy evaluation: a pure function, default-deny, block > ask > allow (arch §2.1)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..contracts.decision import FAIL_OPEN_TAGS, Decision, EffectTag
from .conditions import Env, EvaluationError
from .loader import CompiledPolicy, CompiledRule, tool_matches

DEFAULT_DENY = "default-deny"
EVALUATOR_ERROR = "evaluator-error"
MAX_ARGS_BYTES = 1_000_000


@dataclass(frozen=True)
class SessionState:
    risk_score: float = 0.0
    approved: frozenset[tuple[str, str]] = frozenset()      # (tool, args_hash) approved by a human


@dataclass(frozen=True)
class Evaluation:
    decision: Decision
    rule_id: str
    reason: str
    matched: tuple[str, ...]
    effect_tag: EffectTag
    args_hash: str
    args_valid: bool = True
    approved_by_human: bool = False


def parse_args(arguments: Mapping[str, Any] | str | None) -> tuple[dict[str, Any], bool, str]:
    """Return (args dict, parsed_ok, canonical raw string for hashing). Never raises."""
    if arguments is None:
        return {}, True, "{}"
    if isinstance(arguments, Mapping):
        return dict(arguments), True, _canon(arguments)
    if isinstance(arguments, str):
        if not arguments.strip():
            return {}, True, "{}"
        try:
            value = json.loads(arguments)
        except ValueError:
            return {}, False, arguments
        if isinstance(value, dict):
            return value, True, _canon(value)
        return {}, False, arguments
    return {}, False, repr(arguments)


def _canon(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return repr(value)


def args_hash(arguments: Mapping[str, Any] | str | None) -> str:
    return hashlib.sha256(parse_args(arguments)[2].encode()).hexdigest()


def candidates(policy: CompiledPolicy, tool: str) -> list[CompiledRule]:
    return [r for r in policy.rules if tool_matches(r, tool)]


def _reason(rule: CompiledRule, verb: str) -> str:
    return rule.doc.reason or f"{verb} by rule {rule.doc.id}"


def evaluate(policy: CompiledPolicy, tool: str, arguments: Mapping[str, Any] | str | None,
             session: SessionState | None = None, *, advised_tag: EffectTag | None = None) -> Evaluation:
    session = session or SessionState()
    args, args_ok, canon = parse_args(arguments)
    digest = hashlib.sha256(canon.encode()).hexdigest()
    try:
        tag = policy.tag_for(tool, advised_tag)
    except Exception:                                           # noqa: BLE001
        tag = EffectTag.external
    try:
        if len(canon) > MAX_ARGS_BYTES:
            raise EvaluationError("arguments too large")
        env = Env(args=args, risk_score=session.risk_score, scopes=policy.doc.scopes)
        matched = [r for r in candidates(policy, tool) if r.condition.test(env)]
    except Exception as exc:                                    # noqa: BLE001  (fail closed, see arch §8.6)
        if tag in FAIL_OPEN_TAGS:
            return Evaluation(Decision.allow, f"{EVALUATOR_ERROR}-fail-open",
                              f"Policy could not be evaluated ({type(exc).__name__}); read-only tool allowed",
                              (), tag, digest, args_ok)
        return Evaluation(Decision.block, EVALUATOR_ERROR,
                          f"Policy could not be evaluated ({type(exc).__name__}); action blocked", (), tag, digest, args_ok)
    ids = tuple(r.doc.id for r in matched)
    for effect in (Decision.block, Decision.ask, Decision.allow):
        hit = next((r for r in matched if r.doc.effect is effect), None)
        if hit is None:
            continue
        if effect is Decision.ask and (tool, digest) in session.approved:
            return Evaluation(Decision.allow, hit.doc.id, f"Approved by a human reviewer ({hit.doc.id})", ids, tag,
                              digest, args_ok, approved_by_human=True)
        verb = {Decision.block: "Blocked", Decision.ask: "Needs approval", Decision.allow: "Allowed"}[effect]
        return Evaluation(effect, hit.doc.id, _reason(hit, verb), ids, tag, digest, args_ok)
    default = policy.doc.tag_defaults.get(tag)
    if default is not None:
        decision = Decision(default)
        if decision is Decision.ask and (tool, digest) in session.approved:
            return Evaluation(Decision.allow, f"tag-default:{tag.value}", "Approved by a human reviewer", ids, tag,
                              digest, args_ok, approved_by_human=True)
        return Evaluation(decision, f"tag-default:{tag.value}",
                          f"No rule allows this call; the default for '{tag.value}' tools is {decision.value}",
                          ids, tag, digest, args_ok)
    suffix = "" if args_ok else " (the tool arguments were not valid JSON)"
    return Evaluation(Decision.block, DEFAULT_DENY, f"No policy rule allows this action{suffix}", ids, tag, digest, args_ok)
