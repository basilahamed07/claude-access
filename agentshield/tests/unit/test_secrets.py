import re
import time

import pytest

from agentshield.tenants.crypto import DecryptionError, decrypt_secret, encrypt_secret, generate_master_key
from agentshield.tenants.keys import (
    issue_agent_key,
    issue_user_token,
    looks_like_agent_key,
    verify_secret,
)
from agentshield.tenants.passwords import hash_password, verify_password
from agentshield.tenants.tokens import (
    InvalidToken,
    mint_agent_jwt,
    mint_session,
    verify_agent_jwt,
    verify_session,
)
from agentshield.tenants.urls import UnsafeURL, validate_outbound_url

PEPPER = b"pepper"


def test_agent_key_format_and_prefix():
    k = issue_agent_key(PEPPER)
    assert re.fullmatch(r"ask_live_[A-Za-z0-9_-]{32}", k.plaintext)
    assert k.prefix == k.plaintext[:16] and len(k.prefix) == 16
    assert looks_like_agent_key(k.plaintext)


def test_two_issues_differ_and_hash_is_not_plaintext():
    a, b = issue_agent_key(PEPPER), issue_agent_key(PEPPER)
    assert a.plaintext != b.plaintext and a.hash != b.hash
    assert a.plaintext.encode() not in a.hash


def test_verify_secret_accepts_right_rejects_wrong_and_other_pepper():
    k = issue_agent_key(PEPPER)
    assert verify_secret(PEPPER, k.plaintext, k.hash)
    assert not verify_secret(PEPPER, k.plaintext + "x", k.hash)
    assert not verify_secret(b"other", k.plaintext, k.hash)


def test_user_token_prefix():
    t = issue_user_token(PEPPER)
    assert t.plaintext.startswith("asu_") and len(t.prefix) == 12


def test_crypto_roundtrip_and_wrong_key():
    k1, k2 = generate_master_key().encode(), generate_master_key().encode()
    blob = encrypt_secret(k1, "sk-secret")
    assert b"sk-secret" not in blob
    assert decrypt_secret(k1, blob) == "sk-secret"
    with pytest.raises(DecryptionError):
        decrypt_secret(k2, blob)


def test_password_hash_and_verify():
    h = hash_password("correct horse battery staple")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "correct horse battery staple")
    assert not verify_password(h, "wrong")
    assert not verify_password(None, "anything")


def test_agent_jwt_roundtrip_expiry_and_wrong_type():
    tok = mint_agent_jwt("s", tenant_id="t", agent_id="a", agent_slug="bot")
    claims = verify_agent_jwt("s", tok)
    assert (claims.tenant_id, claims.agent_slug) == ("t", "bot")
    with pytest.raises(InvalidToken):
        verify_agent_jwt("other-secret", tok)
    expired = mint_agent_jwt("s", tenant_id="t", agent_id="a", agent_slug="bot", ttl=-5)
    with pytest.raises(InvalidToken):
        verify_agent_jwt("s", expired)
    session = mint_session("s", user_id="u", tenant_id="t", role="admin", csrf="c")
    with pytest.raises(InvalidToken):
        verify_agent_jwt("s", session)
    assert verify_session("s", session)["role"] == "admin"


def test_jwt_alg_none_is_rejected():
    import base64
    import json
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
    body = base64.urlsafe_b64encode(json.dumps(
        {"typ": "agent", "sub": "bot", "tid": "t", "aid": "a", "exp": int(time.time()) + 100}).encode()).rstrip(b"=")
    with pytest.raises(InvalidToken):
        verify_agent_jwt("s", f"{header.decode()}.{body.decode()}.")


PUBLIC = lambda host, port: ["93.184.216.34"]  # noqa: E731


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data",
    "http://[::1]/",
    "https://10.0.0.5/v1",
    "https://127.0.0.1:8000",
    "https://192.168.1.10",
    "ftp://example.com/x",
    "https://user:pw@example.com",
    "http://example.com",           # plain http, not allow-listed
    "https://[::ffff:10.0.0.1]/",   # IPv4-mapped private
    "file:///etc/passwd",
])
def test_unsafe_urls_rejected(url):
    with pytest.raises(UnsafeURL):
        validate_outbound_url(url, resolver=PUBLIC)


def test_dns_that_resolves_to_private_is_rejected():
    with pytest.raises(UnsafeURL):
        validate_outbound_url("https://rebind.example.com", resolver=lambda h, p: ["192.168.1.2"])


def test_dns_with_mixed_public_and_private_is_rejected():
    with pytest.raises(UnsafeURL):
        validate_outbound_url("https://mixed.example.com", resolver=lambda h, p: ["93.184.216.34", "10.1.1.1"])


def test_public_https_accepted():
    assert validate_outbound_url("https://api.openai.com/v1", resolver=PUBLIC)


def test_allow_listed_private_host_accepted_over_http():
    assert validate_outbound_url("http://vllm:8000/v1", allow_private={"vllm"})
    with pytest.raises(UnsafeURL):
        validate_outbound_url("http://other:8000/v1", allow_private={"vllm"}, resolver=lambda h, p: ["10.0.0.1"])
