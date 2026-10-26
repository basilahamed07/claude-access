import hashlib
from datetime import UTC, datetime

from agentshield.audit.chain import GENESIS, canonical_json, compute_hash, iso, normalise


def env(**over):
    base = {"tenant_id": "00000000-0000-0000-0000-000000000001", "seq": 1, "ts": datetime(2026, 10, 26, 10, 41, 0, 123456, tzinfo=UTC),
            "schema": "agentshield.event/1", "id": "evt_1", "trace_id": "t-1", "module": "gateway",
            "type": "request.received", "severity": "info", "summary": "s", "payload_sha256": "ab" * 32,
            "payload_truncated": False}
    return {**base, **over}


def test_genesis_is_fixed():
    assert GENESIS == hashlib.sha256(b"agentshield-genesis-v1").digest()


def test_canonical_json_is_order_independent_and_compact():
    assert canonical_json({"b": 1, "a": [1, 2]}) == b'{"a":[1,2],"b":1}'


def test_hash_depends_on_prev_and_every_field():
    h = compute_hash(GENESIS, env())
    assert len(h) == 32 and h == compute_hash(GENESIS, env())
    assert h != compute_hash(b"\x01" * 32, env())
    for field, value in [("summary", "x"), ("seq", 2), ("decision", "block"), ("reason", "r"), ("trace_id", "t-2"),
                         ("payload_sha256", "cd" * 32), ("type", "policy.decision")]:
        assert compute_hash(GENESIS, env(**{field: value})) != h, field


def test_db_row_and_event_forms_hash_identically():
    ts = datetime(2026, 10, 26, 10, 41, 0, 123456, tzinfo=UTC)
    from_event = env(ts=iso(ts))
    from_row = env(ts=ts, payload_sha256=bytes.fromhex("ab" * 32), session_id=None)
    assert compute_hash(GENESIS, from_event) == compute_hash(GENESIS, from_row)


def test_normalise_ignores_chain_columns_and_unknown_keys():
    n = normalise({**env(), "prev_hash": b"x", "hash": b"y", "extra": 1})
    assert "prev_hash" not in n and "hash" not in n and "extra" not in n
