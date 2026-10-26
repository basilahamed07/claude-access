"""Short-lived agent JWTs and signed dashboard session cookies (HS256)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import jwt

AGENT_JWT_TTL = 900   # 15 minutes
SESSION_TTL = 12 * 3600


class InvalidToken(Exception):
    pass


@dataclass(frozen=True)
class AgentClaims:
    tenant_id: str
    agent_id: str
    agent_slug: str


def mint_agent_jwt(secret: str, *, tenant_id: str, agent_id: str, agent_slug: str,
                   ttl: int = AGENT_JWT_TTL) -> str:
    now = int(time.time())
    return jwt.encode(
        {"typ": "agent", "sub": agent_slug, "tid": tenant_id, "aid": agent_id, "iat": now, "exp": now + ttl},
        secret, algorithm="HS256")


def verify_agent_jwt(secret: str, token: str) -> AgentClaims:
    try:
        data = jwt.decode(token, secret, algorithms=["HS256"], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError as exc:
        raise InvalidToken(str(exc)) from exc
    if data.get("typ") != "agent":
        raise InvalidToken("wrong token type")
    return AgentClaims(tenant_id=data["tid"], agent_id=data["aid"], agent_slug=data["sub"])


def mint_session(secret: str, *, user_id: str, tenant_id: str, role: str, csrf: str,
                 ttl: int = SESSION_TTL) -> str:
    now = int(time.time())
    return jwt.encode({"typ": "session", "sub": user_id, "tid": tenant_id, "role": role, "csrf": csrf,
                       "iat": now, "exp": now + ttl}, secret, algorithm="HS256")


def verify_session(secret: str, token: str) -> dict[str, Any]:
    try:
        data = jwt.decode(token, secret, algorithms=["HS256"], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError as exc:
        raise InvalidToken(str(exc)) from exc
    if data.get("typ") != "session":
        raise InvalidToken("wrong token type")
    return dict(data)
