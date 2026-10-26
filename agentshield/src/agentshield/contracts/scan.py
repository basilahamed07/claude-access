"""Scan API contract (arch §2.2)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal["clean", "suspicious", "malicious"]


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(min_length=1, max_length=64)
    trust: Literal["untrusted", "semi_trusted"] = "untrusted"
    id: str = Field(default="content", max_length=200)
    text: str
    session_id: str | None = Field(default=None, max_length=200)
    planned_action: dict[str, object] | None = None


class ScanFinding(BaseModel):
    rule_id: str
    category: str = ""
    span: tuple[int, int] | None = None
    text: str = ""
    hidden: bool = False
    layer: str = "rules"


class ScanResult(BaseModel):
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)          # likelihood that the content is hostile (not confidence in the label)
    layers: list[str] = Field(default_factory=list)
    findings: list[ScanFinding] = Field(default_factory=list)
    sanitized_text: str | None = None
    risk_score: float = Field(default=0.0, ge=0, le=1)
    flags: list[str] = Field(default_factory=list)
    scores: dict[str, float] = Field(default_factory=dict)
    ruleset: str | None = None
    action: Literal["passed", "sanitized", "quarantined", "flagged"] = "passed"
    trace_id: str | None = None
