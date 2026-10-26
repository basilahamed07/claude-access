"""Response models. They mirror `agentshield/openapi.json`; `tests/test_contract.py` fails if the two drift."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Decision = Literal["allow", "block", "ask"]
EffectTag = Literal["read", "write", "destructive", "external", "financial", "execute"]
Verdict = Literal["clean", "suspicious", "malicious"]


class Finding(BaseModel):
    model_config = ConfigDict(extra="allow")
    module: str
    span: str | None = None
    rule_id: str | None = None


class CheckResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    decision: Decision
    reason: str
    rule_id: str
    risk_score: float = Field(ge=0, le=1)
    findings: list[Finding] = Field(default_factory=list)
    approval_id: str | None = None
    mode: Literal["enforce", "monitor"] = "enforce"
    would_have: Decision | None = None
    trace_id: str


class ScanFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")
    rule_id: str
    category: str = ""
    span: tuple[int, int] | None = None
    text: str = ""
    hidden: bool = False
    layer: str = "rules"


class ScanResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    verdict: Verdict
    confidence: float
    layers: list[str] = Field(default_factory=list)
    findings: list[ScanFinding] = Field(default_factory=list)
    sanitized_text: str | None = None
    risk_score: float = 0.0
    flags: list[str] = Field(default_factory=list)
    scores: dict[str, float] = Field(default_factory=dict)
    ruleset: str | None = None
    action: Literal["passed", "sanitized", "quarantined", "flagged"] = "passed"
    trace_id: str | None = None


class Approval(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    status: Literal["pending", "approved", "denied", "expired"]
    decision: Decision
    expires_at: str
    decided_at: str | None = None


class UntrustedInput(BaseModel):
    source: str
    id: str
    text: str

    def payload(self) -> dict[str, Any]:
        return self.model_dump()
