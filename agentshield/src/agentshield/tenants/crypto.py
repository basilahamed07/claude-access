"""Provider-key encryption at rest (Fernet). The master key never lives in the database."""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken


class DecryptionError(Exception):
    pass


def generate_master_key() -> str:
    return Fernet.generate_key().decode()


def encrypt_secret(master_key: bytes, plaintext: str) -> bytes:
    return Fernet(master_key).encrypt(plaintext.encode())


def decrypt_secret(master_key: bytes, blob: bytes) -> str:
    try:
        return Fernet(master_key).decrypt(bytes(blob)).decode()
    except InvalidToken as exc:
        raise DecryptionError("cannot decrypt secret with the configured master key") from exc
