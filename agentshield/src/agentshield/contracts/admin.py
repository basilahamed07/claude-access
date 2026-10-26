"""Control-plane request/response models. Separate Create/Update/Read shapes, extra=forbid on input
so clients can never set server-owned fields (OWASP API3)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
RiskTier = Literal["low", "medium", "high"]
AgentMode = Literal["enforce", "monitor"]
KeyMode = Literal["stored", "passthrough"]
Password = Annotated[str, StringConstraints(min_length=12, max_length=200)]


class In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


MAX_VERSION = 1_000_000          # policy versions are small integers; anything bigger would overflow the column


def reject_nulls(data: Any, names: tuple[str, ...]) -> Any:
    """PATCH models: leaving a field out means "no change"; sending null for a required column is an error, not a 500."""
    if isinstance(data, dict):
        bad = [n for n in names if n in data and data[n] is None]
        if bad:
            raise ValueError(f"{', '.join(bad)} cannot be null; omit the field to leave it unchanged")
    return data


# ── auth / tenants ──────────────────────────────────────────────────────────────────────────
class SignupRequest(In):
    tenant_name: str = Field(min_length=2, max_length=100)
    slug: Slug | None = None
    email: EmailStr
    password: Password


class LoginRequest(In):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)


class MeResponse(Out):
    user_id: UUID
    tenant_id: UUID
    email: str
    role: str
    csrf_token: str | None = None


class LoginResponse(Out):
    user_id: UUID
    tenant_id: UUID
    role: str
    csrf_token: str


class TokenResponse(Out):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int


# ── users ───────────────────────────────────────────────────────────────────────────────────
class UserCreate(In):
    email: EmailStr
    password: Password
    role: Literal["admin", "analyst", "viewer"]


class UserUpdate(In):
    role: Literal["admin", "analyst", "viewer"] | None = None
    disabled: bool | None = None
    password: Password | None = None

    @model_validator(mode="before")
    @classmethod
    def _no_null(cls, data: Any) -> Any:
        return reject_nulls(data, ("role", "disabled", "password",))


class UserRead(Out):
    id: UUID
    email: str
    role: str
    created_at: datetime
    disabled_at: datetime | None = None


# ── upstreams ───────────────────────────────────────────────────────────────────────────────
class ModelMapEntry(In):
    model: str = Field(min_length=1, max_length=200)
    input_micro_usd_per_mtok: int = Field(default=0, ge=0)
    output_micro_usd_per_mtok: int = Field(default=0, ge=0)


class UpstreamCreate(In):
    name: str = Field(min_length=1, max_length=100)
    kind: Literal["anthropic", "openai", "openai_compat"]
    base_url: str = Field(min_length=8, max_length=500)
    api_key: str | None = Field(default=None, max_length=2000, repr=False)
    model_map: dict[str, ModelMapEntry] = Field(default_factory=dict)
    judge_model: str | None = Field(default=None, max_length=200)


class UpstreamUpdate(In):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    base_url: str | None = Field(default=None, min_length=8, max_length=500)
    api_key: str | None = Field(default=None, max_length=2000, repr=False)
    model_map: dict[str, ModelMapEntry] | None = None
    judge_model: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _no_null(cls, data: Any) -> Any:
        return reject_nulls(data, ("name", "base_url", "model_map",))


class UpstreamTestRequest(In):
    model: str | None = Field(default=None, max_length=200)


class UpstreamTestResult(Out):
    ok: bool
    status: int | None = None
    latency_ms: int
    error: str | None = None


class UpstreamRead(Out):
    id: UUID
    name: str
    kind: str
    base_url: str
    has_key: bool
    model_map: dict[str, ModelMapEntry]
    judge_model: str | None = None
    created_at: datetime


# ── agents / keys ───────────────────────────────────────────────────────────────────────────
class AgentCreate(In):
    slug: Slug
    name: str = Field(min_length=1, max_length=100)
    owner: str = Field(min_length=1, max_length=200)
    purpose: str = Field(default="", max_length=1000)
    risk_tier: RiskTier = "medium"
    mode: AgentMode = "monitor"
    key_mode: KeyMode = "stored"
    upstream_id: UUID | None = None


class AgentUpdate(In):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    owner: str | None = Field(default=None, min_length=1, max_length=200)
    purpose: str | None = Field(default=None, max_length=1000)
    risk_tier: RiskTier | None = None
    mode: AgentMode | None = None
    key_mode: KeyMode | None = None
    upstream_id: UUID | None = None
    status: Literal["active", "suspended"] | None = None

    @model_validator(mode="before")
    @classmethod
    def _no_null(cls, data: Any) -> Any:
        return reject_nulls(data, ("name", "owner", "purpose", "risk_tier", "mode", "key_mode", "status",))


class AgentRead(Out):
    id: UUID
    slug: str
    name: str
    owner: str
    purpose: str
    risk_tier: str
    mode: str
    key_mode: str
    upstream_id: UUID | None = None
    active_policy_version: int | None = None
    status: str
    last_seen_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    key_count: int = 0


class KeyIssued(Out):
    id: UUID
    key: str
    prefix: str
    created_at: datetime
    expires_at: datetime | None = None


class KeyRead(Out):
    id: UUID
    prefix: str
    created_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None


class RotateRequest(In):
    overlap_seconds: int = Field(default=86400, ge=0, le=604800)


class Snippet(Out):
    lang: str
    code: str


class Page[T](BaseModel):
    items: list[T]
    next_cursor: str | None = None


# ── tenant settings ───────────────────────────────────────────────────────────────────────────
class Retention(In):
    payload_days: int = Field(default=30, ge=7)
    envelope_days: int = Field(default=180, ge=180)
    incident_days: int = Field(default=1095, ge=365)


class TenantSettings(In):
    on_malicious: Literal["sanitize", "quarantine", "flag"] = "sanitize"
    mark_untrusted: bool = True
    webhook_url: str | None = Field(default=None, max_length=500)
    retention: Retention = Field(default_factory=Retention)
    judge_upstream_id: UUID | None = None

    @field_validator("webhook_url")
    @classmethod
    def _blank_is_none(cls, v: str | None) -> str | None:
        return v or None


class TenantSettingsPatch(In):
    on_malicious: Literal["sanitize", "quarantine", "flag"] | None = None
    mark_untrusted: bool | None = None
    webhook_url: str | None = None
    retention: Retention | None = None
    judge_upstream_id: UUID | None = None


class EventRead(Out):
    seq: int
    ts: datetime
    id: str
    trace_id: str
    session_id: UUID | None = None
    agent_slug: str | None = None
    end_user: str | None = None
    module: str
    type: str
    decision: str | None = None
    rule_id: str | None = None
    reason: str | None = None
    severity: str
    summary: str
    payload_truncated: bool = False
    payload_available: bool = False
    hash: str
    payload: dict[str, object] | None = None


# ── policies ────────────────────────────────────────────────────────────────────────────────────
class PolicyVersionCreate(In):
    yaml: str = Field(min_length=1, max_length=300_000)
    version: int | None = Field(default=None, ge=1, le=MAX_VERSION)
    activate: bool = False


class PolicyVersionRead(Out):
    version: int
    created_at: datetime
    created_by: UUID
    sha256: str
    active: bool = False
    yaml: str | None = None
    parsed: dict[str, object] | None = None


# ── approvals ───────────────────────────────────────────────────────────────────────────────────
class ApprovalRead(Out):
    id: UUID
    agent_slug: str
    session_id: UUID
    trace_id: str
    tool: str
    args_redacted: dict[str, object]
    rule_id: str
    status: str
    decided_by: UUID | None = None
    decided_by_email: str | None = None
    decided_at: datetime | None = None
    note: str | None = None
    expires_at: datetime
    created_at: datetime


class ApprovalDecision(In):
    approve: bool
    note: str | None = Field(default=None, max_length=500)


class AgentApprovalRead(Out):
    id: UUID
    status: Literal["pending", "approved", "denied", "expired"]
    decision: Literal["allow", "block", "ask"]
    expires_at: datetime
    decided_at: datetime | None = None


# ── scan rules ──────────────────────────────────────────────────────────────────────────────────
class ScanRulesPut(In):
    yaml: str = Field(min_length=1, max_length=300_000)


class ScanRuleRead(Out):
    id: str
    category: str
    weight: float
    description: str = ""
    source: Literal["default", "tenant"]


class ScanRulesRead(Out):
    version: str
    rules: list[ScanRuleRead]


# ── sessions, replay, incidents, alerts, stats (B17) ─────────────────────────────────────────────
class SessionRead(Out):
    id: UUID
    agent_slug: str
    end_user: str | None = None
    user_request: str | None = None
    risk_score: float
    started_at: datetime
    last_seen_at: datetime
    calls: int = 0
    blocked: int = 0


class TimelineTrace(Out):
    trace_id: str
    started_at: datetime
    events: list[EventRead]


class Timeline(Out):
    session: SessionRead
    traces: list[TimelineTrace]
    truncated: bool = False


class ReplayStep(Out):
    seq: int
    ts: datetime
    trace_id: str
    tool: str
    effect_tag: str | None = None
    recorded_decision: str | None = None
    recorded_rule: str | None = None
    replay_decision: str | None = None
    replay_rule: str | None = None
    replay_reason: str | None = None
    changed: bool = False
    skipped: str | None = None


class ReplayRequest(In):
    policy_version: int | None = Field(default=None, ge=1, le=MAX_VERSION)


class ReplayResult(Out):
    session_id: UUID
    policy_version: int | None
    compared: int
    skipped: int
    changed: int
    redacted_input: bool = True
    steps: list[ReplayStep]


class SimulateRequest(In):
    version: int = Field(ge=1, le=MAX_VERSION)
    session_ids: list[UUID] | None = Field(default=None, max_length=200)
    since: str | None = Field(default=None, pattern=r"^[1-9]\d{0,2}[hd]$")


class SimulateResult(Out):
    version: int
    sessions: int
    compared: int
    skipped: int
    changed: int
    newly_blocked: int
    newly_allowed: int
    newly_asked: int
    diffs: list[ReplayStep]
    truncated: bool = False


class IncidentCreate(In):
    session_id: UUID
    title: str = Field(min_length=1, max_length=200)
    severity: Literal["low", "medium", "high", "critical"] = "high"


class IncidentPatch(In):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    status: Literal["open", "investigating", "closed"] | None = None


class IncidentRead(Out):
    id: UUID
    session_id: UUID
    title: str
    severity: str
    status: str
    created_by: UUID
    created_at: datetime
    updated_at: datetime


class AlertRead(Out):
    kind: Literal["blocked_call", "malicious_content", "approval_expired", "budget_exceeded", "audit_gap"]
    ts: datetime
    seq: int
    severity: str
    summary: str
    agent_slug: str | None = None
    session_id: UUID | None = None
    trace_id: str
    rule_id: str | None = None


class CountBy(Out):
    key: str
    count: int


class SeriesPoint(Out):
    ts: datetime
    allowed: int
    blocked: int
    asked: int


class StatsOverview(Out):
    window: str
    calls: int
    allowed: int
    blocked: int
    asked: int
    malicious_scans: int
    approvals_pending: int
    active_sessions: int
    risky_sessions: int
    top_rules: list[CountBy]
    top_agents: list[CountBy]
    series: list[SeriesPoint]


class ExportVerification(Out):
    verified: bool
    checked: int
    first_seq: int | None = None
    last_seq: int | None = None
    first_bad_seq: int | None = None
    reason: str | None = None


class SessionExport(Out):
    exported_at: datetime
    session: SessionRead
    events: list[EventRead]
    chain_head: dict[str, object] | None = None
    verification: ExportVerification
