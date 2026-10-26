"""Environment-driven settings (prefix AGENTSHIELD_)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGENTSHIELD_", env_file=".env", extra="ignore")

    env: Literal["dev", "test", "prod"] = "dev"
    database_url: str = "postgresql+asyncpg://agentshield_app@localhost:5432/agentshield"
    owner_database_url: str = "postgresql+asyncpg://postgres@localhost:5432/agentshield"
    worker_database_url: str | None = None
    redis_url: str = "redis://localhost:6379/0"

    master_key: str = Field(default="", description="Fernet key for provider secrets")
    key_pepper: str = Field(default="", description="HMAC pepper for agent keys / tokens")
    jwt_secret: str = Field(default="", description="HS256 secret for agent JWTs")
    session_secret: str = Field(default="", description="signs dashboard session cookies")

    signup: Literal["open", "closed"] = "open"
    allow_private_upstreams: str = Field(
        default="", description="comma-separated hosts allowed over http/private ranges"
    )
    cors_origins: str = "http://localhost:5173"
    cookie_secure: bool = True

    classifier: Literal["null", "stub", "protectai_v2", "prompt_guard_2_22m"] = "null"
    classifier_dir: str = ""
    rules_path: str = ""

    proxy_max_body_bytes: int = 2 * 1024 * 1024
    scan_max_item_bytes: int = 1_000_000
    upstream_max_bytes: int = 10 * 1024 * 1024
    approval_ttl_seconds: int = 300
    approval_allowance_seconds: int = 900
    judge_timeout_seconds: float = 1.5

    spool_dir: str = "/tmp/agentshield-spool"  # noqa: S108

    @property
    def private_hosts(self) -> set[str]:
        return {h.strip().lower() for h in self.allow_private_upstreams.split(",") if h.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
