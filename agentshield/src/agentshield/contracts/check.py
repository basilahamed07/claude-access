"""Check API contract (prompt §9 shape plus approval/mode fields; api §A.4.1)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .decision import Decision, EffectTag


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UntrustedInput(Strict):
    source: str = Field(min_length=1, max_length=64)
    id: str = Field(min_length=1, max_length=200)
    text: str = Field(max_length=1_000_000)


class Action(Strict):
    tool: str = Field(min_length=1, max_length=200)
    arguments: dict[str, Any] = Field(default_factory=dict)
    effect_tag: EffectTag | None = None


class CheckContext(Strict):
    user_request: str | None = Field(default=None, max_length=100_000)
    end_user: str | None = Field(default=None, max_length=200)
    untrusted_inputs: list[UntrustedInput] = Field(default_factory=list, max_length=50)


class CheckRequest(Strict):
    agent_id: str
    tenant: str
    session_id: str = Field(min_length=1, max_length=200)
    action: Action
    context: CheckContext = Field(default_factory=CheckContext)
    wait_seconds: int = Field(default=0, ge=0, le=30)


class Finding(BaseModel):
    model_config = ConfigDict(extra="allow")
    module: str
    span: str | None = None
    rule_id: str | None = None


class CheckResponse(BaseModel):
    decision: Decision
    reason: str
    rule_id: str
    risk_score: float = Field(ge=0, le=1)
    findings: list[Finding] = Field(default_factory=list)
    approval_id: str | None = None
    mode: Literal["enforce", "monitor"] = "enforce"
    would_have: Decision | None = None
    trace_id: str
