"""The authenticated caller. `tenant_id` always comes from a credential, never from the request."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

Role = Literal["viewer", "analyst", "admin"]
ROLE_RANK: dict[str, int] = {"viewer": 1, "analyst": 2, "admin": 3}


@dataclass(frozen=True)
class TenantContext:
    tenant_id: UUID
    actor: Literal["agent", "user"]
    actor_id: UUID
    agent_slug: str | None = None
    role: Role | None = None
    auth_method: str = ""

    def has_role(self, minimum: Role) -> bool:
        return self.role is not None and ROLE_RANK[self.role] >= ROLE_RANK[minimum]
