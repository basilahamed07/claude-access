"""Shadow AI contracts (design §2.4): log ingest, the inventory of AI tools seen, and ingest tokens."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

Classification = Literal["approved", "tolerated", "blocked", "unknown"]
Format = Literal["squid", "common", "dns", "csv", "records"]
MAX_LINES = 20_000
MAX_BODY_BYTES = 5 * 1024 * 1024


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IngestBody(_In):
    source: Literal["proxy", "dns"]
    format: Format
    batch_id: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9._:-]+$")
    team: str | None = Field(default=None, min_length=1, max_length=100)
    lines: list[str] | None = Field(default=None, max_length=MAX_LINES)
    records: list[dict[str, Any]] | None = Field(default=None, max_length=MAX_LINES)

    @model_validator(mode="after")
    def _shape(self) -> IngestBody:
        if self.format == "records":
            if self.records is None or self.lines is not None:
                raise ValueError("format 'records' takes 'records' and no 'lines'")
        elif self.lines is None or self.records is not None:
            raise ValueError(f"format '{self.format}' takes 'lines' and no 'records'")
        return self


class IngestResult(BaseModel):
    batch_id: str
    duplicate: bool
    accepted: int
    rejected: int
    reasons: list[str]
    tools_seen: int
    new_tools: int


class AiToolRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    domain: str
    vendor: str | None = None
    category: str | None = None
    risk: str | None = None
    classification: Classification
    team: str | None = None
    source: str | None = None
    reason: str | None = None
    hits: int
    bytes_out: int
    users_count: int
    first_seen: datetime
    last_seen: datetime
    suggested_alternative: str | None = None


class AiToolUpdate(_In):
    classification: Literal["approved", "tolerated", "blocked"]
    suggested_alternative: str | None = Field(default=None, max_length=1000)


class TokenCreate(_In):
    label: str = Field(min_length=1, max_length=100)


class TokenRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    prefix: str
    label: str
    created_at: datetime
    revoked_at: datetime | None = None


class TokenIssued(TokenRead):
    token: str = Field(description="Shown once; store it in the log shipper's configuration.")
