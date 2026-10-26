"""Password hashing: argon2id with m=64 MiB, t=3, p=1 (api spec §A.2)."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=1)
# A real hash of a random string: verifying against it burns the same time as a real user lookup,
# so unknown e-mails and wrong passwords are indistinguishable by timing.
_DUMMY_HASH = _hasher.hash("agentshield-timing-equaliser")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerificationError, InvalidHashError):
        return False
