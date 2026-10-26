import json

import pytest

from agentshield.audit.redact import luhn_ok, redact


def r(value, **kw):
    return redact(value, **kw)


@pytest.mark.parametrize(("secret", "kind"), [
    ("sk-ant-api03-abcdefghijklmnopqrstuvwx", "anthropic_key"),
    ("sk-proj-abcdefghijklmnopqrstuvwxyz123456", "openai_key"),
    ("sk-live-supersecret1234567890", "openai_key"),
    ("AKIAIOSFODNN7EXAMPLE", "aws_key"),
    ("ghp_" + "a" * 36, "github_token"),
    ("github_pat_11ABCDEFG0abcdefghijkl_xyz", "github_token"),
    ("xoxb-1234567890-abcdefghij", "slack_token"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcdefghijklmnop", "jwt"),
    ("Bearer abcdefghijklmnopqrstuvwxyz", "bearer"),
    ("ask_live_abcdefghijklmnopqrstuvwxyz123456", "agentshield_key"),
    ("asu_abcdefghijklmnopqrstuvwxyz123456", "agentshield_token"),
    ("AIzaSyA-1234567890abcdefghijklmnopqrstuv", "google_key"),
])
def test_secrets_are_masked(secret, kind):
    out = r(f"my key is {secret} ok")
    assert secret not in out.value and f"[REDACTED:{kind}:" in out.value and kind in out.kinds


def test_private_key_block_is_masked():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"
    assert "MIIEow" not in r(f"x {pem} y").value


def test_card_numbers_only_when_luhn_valid():
    assert "[REDACTED:card:" in r("card 4111 1111 1111 1111 thanks").value
    assert "[REDACTED:card:" in r("4111-1111-1111-1111").value
    assert r("order 1234567890123456 shipped").value == "order 1234567890123456 shipped"   # not Luhn-valid
    assert luhn_ok("4111111111111111") and not luhn_ok("4111111111111112")


def test_email_keeps_domain_hides_local_part_when_pii_on():
    out = r("send to alice.smith@unknown.com now").value
    assert "alice.smith" not in out and out.endswith("@unknown.com now") and "[REDACTED:email:" in out
    assert r("a@x.com and A@X.com").value.count("[REDACTED:email:") == 2


def test_pii_off_keeps_emails_and_phones_but_still_masks_secrets():
    out = r("mail alice@example.com key sk-ant-api03-abcdefghijklmnopqrstuvwx", pii=False).value
    assert "alice@example.com" in out and "sk-ant" not in out


def test_phone_numbers_masked():
    assert "[REDACTED:phone:" in r("call +44 20 7946 0958 today").value
    assert "[REDACTED:phone:" in r("call (555) 123-4567 today").value
    assert r("version 1.2.3 build 20241026").value == "version 1.2.3 build 20241026"


def test_same_value_gives_same_tag_so_repeats_correlate():
    a = r("sk-ant-api03-abcdefghijklmnopqrstuvwx").value
    b = r("again sk-ant-api03-abcdefghijklmnopqrstuvwx").value
    assert a in b


def test_nested_structures_and_sensitive_keys():
    payload = {"headers": {"Authorization": "Basic Zm9vOmJhcg==", "x-api-key": "plain-key", "Accept": "json"},
               "args": [{"password": "hunter2", "note": "token sk-ant-api03-abcdefghijklmnopqrstuvwx"}],
               "n": 5, "ok": True, "none": None}
    out = r(payload).value
    dumped = json.dumps(out)
    for secret in ("Zm9vOmJhcg", "plain-key", "hunter2", "sk-ant-api03"):
        assert secret not in dumped
    assert out["headers"]["Accept"] == "json" and out["n"] == 5 and out["ok"] is True and out["none"] is None
    assert "secret_field" in r(payload).kinds


def test_non_secrets_untouched_and_input_not_mutated():
    original = {"msg": "Summarize my unread mail", "list": [1, 2, {"a": "b"}]}
    snapshot = json.dumps(original)
    assert r(original).value == original and json.dumps(original) == snapshot


def test_pathological_depth_does_not_blow_the_stack():
    deep: dict = {}
    cur = deep
    for _ in range(200):
        cur["x"] = {}
        cur = cur["x"]
    assert "too_deep" in json.dumps(r(deep).value)
