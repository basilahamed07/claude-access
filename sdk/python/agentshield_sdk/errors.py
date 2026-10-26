"""Exceptions. Messages never contain the API key."""

from __future__ import annotations


class AgentShieldError(Exception):
    """Base class."""


class Blocked(AgentShieldError):
    """The action must not run. `rule_id` says why: a policy rule, or one of the SDK's own
    (`agentshield-unreachable`, `approval-denied`, `approval-timeout`)."""

    def __init__(self, reason: str, rule_id: str, trace_id: str | None = None, decision: str = "block") -> None:
        super().__init__(f"{reason} (rule {rule_id}" + (f", trace {trace_id})" if trace_id else ")"))
        self.reason = reason
        self.rule_id = rule_id
        self.trace_id = trace_id
        self.decision = decision


class Unreachable(AgentShieldError):
    """AgentShield could not decide: network failure, timeout, 5xx, rate limit or an unreadable reply."""


class AuthError(AgentShieldError):
    """The API key or the agent id/tenant do not match. This is a configuration error, never treated as an outage."""
