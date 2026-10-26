"""Compiled-policy cache. Versions are immutable, so a (agent, version) entry never goes stale."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from ..db.tenant_tx import tenant_tx
from .loader import CompiledPolicy, parse_policy

EMPTY_POLICY = parse_policy("version: 1\n")        # an agent with no active policy: everything is default-deny


class PolicyCache:
    def __init__(self, maxsize: int = 512) -> None:
        self.maxsize = maxsize
        self._d: OrderedDict[tuple[Any, int], CompiledPolicy] = OrderedDict()

    async def get(self, engine: AsyncEngine, tenant_id: UUID | str, agent_id: UUID, version: int | None) -> CompiledPolicy:
        if version is None:
            return EMPTY_POLICY
        key = (agent_id, version)
        hit = self._d.get(key)
        if hit is not None:
            self._d.move_to_end(key)
            return hit
        async with tenant_tx(engine, tenant_id) as conn:
            yaml_text = (await conn.execute(text("select yaml from policy_versions where agent_id = :a and version = :v"),
                                            {"a": agent_id, "v": version})).scalar_one_or_none()
        if yaml_text is None:
            return EMPTY_POLICY
        policy = parse_policy(yaml_text)
        self._d[key] = policy
        if len(self._d) > self.maxsize:
            self._d.popitem(last=False)
        return policy
