"""MCP server registry contracts (design §2.3)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

Capability = Literal["exec", "filesystem", "network", "database", "external", "credentials"]
Verdict = Literal["pending", "approved", "approved_with_limits", "rejected", "suspended"]


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolManifest(_In):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=20_000)
    inputSchema: dict[str, Any] = Field(default_factory=dict)  # noqa: N815  (MCP's own field name)


class McpServerCreate(_In):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,40}$")
    owner: str = Field(min_length=1, max_length=200)
    purpose: str = Field(default="", max_length=1000)
    url: str | None = Field(default=None, max_length=500)
    tools: list[ToolManifest] | None = Field(default=None, max_length=200)
    pinned_version: str = Field(default="unversioned", max_length=100)
    declared_capabilities: list[Capability] = Field(default_factory=list)
    source_files: dict[str, str] | None = None
    auth_token: str | None = Field(default=None, max_length=2000, repr=False)

    @model_validator(mode="after")
    def _one_source(self) -> McpServerCreate:
        if not self.url and not self.tools:
            raise ValueError("give either the server's url or its tool list")
        if self.url and self.tools:
            raise ValueError("give the url or the tool list, not both")
        if self.source_files is not None:
            if len(self.source_files) > 50 or any(len(v) > 200_000 for v in self.source_files.values()):
                raise ValueError("at most 50 source files of 200 KB each")
        return self


class McpApprove(_In):
    allowed_tools: list[str] | None = Field(default=None, max_length=200)
    acknowledge_findings: bool = False


class McpServerRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    name: str
    owner: str
    purpose: str
    url: str | None = None
    pinned_version: str
    verdict: Verdict
    declared_capabilities: list[str] = Field(default_factory=list)
    allowed_tools: list[str] | None = None
    fingerprint: str | None = None
    approved_fingerprint: str | None = None
    tool_count: int = 0
    has_auth: bool = False
    scanned_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class McpServerDetail(McpServerRead):
    tools: list[dict[str, Any]] = Field(default_factory=list)
    report: dict[str, Any] | None = None
