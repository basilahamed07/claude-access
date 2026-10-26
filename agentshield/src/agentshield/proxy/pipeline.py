"""What the proxy hands to whoever decides about tool calls (the policy layer plugs in here)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import Request

from ..tenants.context import TenantContext
from .sessions import SessionRef
from .tools import ToolJudge


@dataclass
class ProxyCall:
    request: Request
    ctx: TenantContext
    session: SessionRef
    trace_id: str
    agent: dict[str, Any]          # slug, mode, risk_tier, active_policy_version, ...
    api: Literal["anthropic", "openai"]
    user_request: str | None
    budget_unavailable: bool = False


JudgeFactory = Callable[[ProxyCall], ToolJudge]
