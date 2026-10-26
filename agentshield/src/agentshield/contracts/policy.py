"""Policy document schema (arch §2.1). Validated by pydantic; conditions are validated by `policy.conditions`."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .decision import Decision, EffectTag

RuleId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_.:-]{0,63}$")]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Budgets(Strict):
    max_cost_usd_per_day: float | None = Field(default=None, gt=0)
    max_calls_per_day: int | None = Field(default=None, gt=0)
    max_tokens_per_day: int | None = Field(default=None, gt=0)
    max_rpm: int | None = Field(default=None, gt=0)


class ToolSpec(Strict):
    effect_tag: EffectTag
    server: str | None = None


class RuleDoc(Strict):
    id: RuleId
    effect: Decision
    tool: str = Field(min_length=1, max_length=200)
    effect_tag: EffectTag | None = None
    when: Any = None
    reason: str | None = Field(default=None, max_length=500)
    server: str | None = None       # reserved for the MCP registry (stage 5)


class PolicyDoc(Strict):
    version: Literal[1]
    agent: str | None = None
    default: Literal["deny"] = "deny"
    budgets: Budgets = Field(default_factory=Budgets)
    scopes: dict[str, list[str]] = Field(default_factory=dict)
    tools: dict[str, ToolSpec] = Field(default_factory=dict)
    tag_defaults: dict[EffectTag, Literal["ask", "block"]] = Field(default_factory=dict)
    rules: list[RuleDoc] = Field(default_factory=list, max_length=500)
