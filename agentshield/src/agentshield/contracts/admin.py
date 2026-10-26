"""Control-plane request/response models. Separate Create/Update/Read shapes, extra=forbid on input
so clients can never set server-owned fields (OWASP API3)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints, field_validator

Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
RiskTier = Literal["low", "medium", "high"]
AgentMode = Literal["enforce", "monitor"]
KeyMode = Literal["stored", "passthrough"]
Password = Annotated[str, StringConstraints(min_length=12, max_length=200)]


class In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


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
    webhook_url: str | None = Field(default=None, max_length=500)
    retention: Retention = Field(default_factory=Retention)
    judge_upstream_id: UUID | None = None

    @field_validator("webhook_url")
    @classmethod
    def _blank_is_none(cls, v: str | None) -> str | None:
        return v or None


class TenantSettingsPatch(In):
    on_malicious: Literal["sanitize", "quarantine", "flag"] | None = None
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
    version: int | None = Field(default=None, ge=1)
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
