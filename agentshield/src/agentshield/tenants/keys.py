"""Agent / user API secrets: random, shown once, stored only as HMAC-SHA256 (arch §4.1)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

AGENT_KEY_PREFIX = "ask_live_"
USER_TOKEN_PREFIX = "asu_"
AGENT_PREFIX_LEN = 16   # "ask_live_" + 7 random chars, used for lookup and display
USER_PREFIX_LEN = 12    # "asu_" + 8 random chars


@dataclass(frozen=True)
class IssuedSecret:
    plaintext: str
    hash: bytes
    prefix: str


def hash_secret(pepper: bytes, plaintext: str) -> bytes:
    return hmac.new(pepper, plaintext.encode(), hashlib.sha256).digest()


def issue_secret(kind_prefix: str, pepper: bytes, prefix_len: int) -> IssuedSecret:
    plaintext = f"{kind_prefix}{secrets.token_urlsafe(24)}"   # 24 bytes -> exactly 32 url-safe chars
    return IssuedSecret(plaintext, hash_secret(pepper, plaintext), plaintext[:prefix_len])


def issue_agent_key(pepper: bytes) -> IssuedSecret:
    return issue_secret(AGENT_KEY_PREFIX, pepper, AGENT_PREFIX_LEN)


def issue_user_token(pepper: bytes) -> IssuedSecret:
    return issue_secret(USER_TOKEN_PREFIX, pepper, USER_PREFIX_LEN)


def verify_secret(pepper: bytes, presented: str, stored_hash: bytes) -> bool:
    return hmac.compare_digest(hash_secret(pepper, presented), bytes(stored_hash))


def looks_like_agent_key(token: str) -> bool:
    return token.startswith(AGENT_KEY_PREFIX) and len(token) >= AGENT_PREFIX_LEN + 8


def looks_like_user_token(token: str) -> bool:
    return token.startswith(USER_TOKEN_PREFIX)
