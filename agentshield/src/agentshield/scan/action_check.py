"""Deterministic check of a planned tool call against the user's original request (arch §2.2, step 6).

Content that hijacks an agent usually pushes it toward a recipient or URL the user never mentioned. If a tool
argument names a domain/address that is neither mentioned in the user's request nor on the policy's approved
list, the call "went somewhere new" and the session risk rises. v1 checks destinations only; it does not try to
judge whether the *tool* was needed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..policy.conditions import domain_matches, extract_domains

ACTION_RISK = 0.2
_MAX_DEPTH = 6


@dataclass
class ActionCheck:
    ok: bool
    reason: str = ""
    unexpected: list[str] = field(default_factory=list)


def _strings(value: Any, depth: int = 0) -> list[str]:
    if depth > _MAX_DEPTH:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v, depth + 1)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _strings(v, depth + 1)]
    return []


def action_in_scope(user_request: str | None, tool: str, arguments: dict[str, Any] | None,
                    allowed_domains: set[str]) -> ActionCheck:
    if not user_request or not arguments:
        return ActionCheck(True)
    request_low = user_request.lower()
    mentioned = {d for d in extract_domains(user_request) if d}
    unexpected: list[str] = []
    for text in _strings(arguments):
        for domain in extract_domains(text):
            if domain is None or domain in mentioned or domain in request_low:
                continue
            if any(domain_matches(domain, p) for p in allowed_domains):
                continue
            if domain not in unexpected:
                unexpected.append(domain)
    if unexpected:
        return ActionCheck(False, f"{tool} targets {', '.join(unexpected)}, which the user's request did not mention",
                           unexpected)
    return ActionCheck(True)


def policy_domains(policy: Any) -> set[str]:
    """Every domain the policy itself treats as approved (values of domain_in conditions)."""
    out: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("op") in {"domain_in", "not_domain_in"} and isinstance(node.get("value"), list):
                out.update(str(v).lower() for v in node["value"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    for rule in policy.doc.rules:
        walk(rule.when)
    return {d for d in out if re.match(r"^(\*\.)?[a-z0-9.-]+$", d)}
