from pathlib import Path

import pytest

from agentshield.contracts.decision import Decision, EffectTag
from agentshield.policy.evaluator import (
    DEFAULT_DENY,
    EVALUATOR_ERROR,
    SessionState,
    args_hash,
    evaluate,
    parse_args,
)
from agentshield.policy.loader import parse_policy

SAMPLE = parse_policy((Path(__file__).resolve().parent.parent / "fixtures" / "policies" / "email_reader.yaml").read_text())


def pol(rules: str, extra: str = "") -> object:
    return parse_policy(f"version: 1\n{extra}\nrules:\n{rules}\n")


def ev(policy, tool, args=None, risk=0.0, approved=frozenset(), **kw):
    return evaluate(policy, tool, args, SessionState(risk, approved), **kw)


# ── default deny and precedence ─────────────────────────────────────────────────────────────────
def test_unmatched_tool_is_default_deny():
    r = ev(SAMPLE, "launch_missiles", {})
    assert (r.decision, r.rule_id) == (Decision.block, DEFAULT_DENY) and r.effect_tag is EffectTag.external


def test_empty_policy_denies_everything():
    assert ev(parse_policy("version: 1\n"), "read_email", {"folder": "INBOX"}).rule_id == DEFAULT_DENY


def test_allow_only():
    r = ev(SAMPLE, "read_email", {"folder": "INBOX"})
    assert (r.decision, r.rule_id) == (Decision.allow, "allow-read-mail") and r.effect_tag is EffectTag.read


def test_block_beats_allow():
    p = pol("  - {id: a, effect: allow, tool: x}\n  - {id: b, effect: block, tool: x, reason: nope}")
    r = ev(p, "x", {})
    assert (r.decision, r.rule_id, r.reason) == (Decision.block, "b", "nope") and r.matched == ("a", "b")


def test_ask_beats_allow_and_block_beats_ask():
    p = pol("  - {id: a, effect: allow, tool: x}\n  - {id: q, effect: ask, tool: x}")
    assert ev(p, "x", {}).decision is Decision.ask
    p = pol("  - {id: q, effect: ask, tool: x}\n  - {id: b, effect: block, tool: x}\n  - {id: a, effect: allow, tool: x}")
    assert ev(p, "x", {}).rule_id == "b"


def test_first_matching_rule_of_the_winning_effect_names_the_decision():
    p = pol("  - {id: b1, effect: block, tool: x}\n  - {id: b2, effect: block, tool: x}")
    assert ev(p, "x", {}).rule_id == "b1"


def test_star_and_glob_tool_patterns():
    p = pol("  - {id: all, effect: block, tool: '*', when: {session: risk_score, op: gte, value: 0.5}}\n"
            "  - {id: g, effect: allow, tool: 'read_*'}")
    assert ev(p, "read_anything", {}).decision is Decision.allow
    assert ev(p, "write_thing", {}).rule_id == DEFAULT_DENY
    assert ev(p, "read_anything", {}, risk=0.5).rule_id == "all"


def test_tool_name_must_match_exactly():
    p = pol("  - {id: a, effect: allow, tool: read_email}")
    for name in ("read_email2", "READ_EMAIL", "read_emai", " read_email"):
        assert ev(p, name, {}).rule_id == DEFAULT_DENY


# ── session risk (M2 tightens M1) ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize(("risk", "blocked"), [(0.0, False), (0.79, False), (0.8, True), (0.99, True), (1.0, True)])
def test_tighten_on_risk_boundary(risk, blocked):
    r = ev(SAMPLE, "read_email", {"folder": "INBOX"}, risk=risk)
    assert (r.decision is Decision.block) is blocked
    if blocked:
        assert r.rule_id == "tighten-on-risk" and r.reason == "Session risk too high"


# ── operators ───────────────────────────────────────────────────────────────────────────────────
def cond(op, value, arg="a", effect="allow"):
    import json
    return pol(f"  - {{id: r, effect: {effect}, tool: t, when: {{arg: {arg}, op: {op}, value: {json.dumps(value)}}}}}")


@pytest.mark.parametrize(("op", "value", "arg", "expected"), [
    ("eq", "x", "x", True), ("eq", "x", "y", False), ("eq", 5, 5, True), ("eq", 5, "5", False), ("eq", True, True, True),
    ("eq", True, 1, False), ("ne", "x", "y", True), ("ne", "x", "x", False),
    ("in", ["a", "b"], "a", True), ("in", ["a", "b"], "c", False), ("in", ["a", "b"], ["a", "b"], True),
    ("in", ["a", "b"], ["a", "c"], False), ("in", [1, 2], 2, True), ("in", ["a"], [], False),
    ("not_in", ["a", "b"], "c", True), ("not_in", ["a", "b"], "a", False), ("not_in", ["a"], ["b", "a"], False),
    ("glob", "*.pdf", "report.pdf", True), ("glob", "*.pdf", "report.txt", False), ("glob", "a?c", "abc", True),
    ("regex", r"^\d{3}-\d{4}$", "555-1234", True), ("regex", r"^\d{3}-\d{4}$", "555-12345", False),
    ("regex", "evil", ["fine", "very evil"], True), ("regex", "x", 5, False),
    ("gt", 1000, 1001, True), ("gt", 1000, 1000, False), ("gte", 1000, 1000, True), ("lt", 10, 9.5, True),
    ("lte", 10, 10, True), ("gt", 1000, "5000", True), ("gt", 1000, "five", False), ("gt", 1000, None, False),
    ("gt", 1000, True, False), ("gt", 1000, [1], False),
    ("domain_in", ["acme.com"], "bob@acme.com", True), ("domain_in", ["acme.com"], "bob@evil.com", False),
    ("domain_in", ["acme.com"], ["a@acme.com", "b@acme.com"], True),
    ("domain_in", ["acme.com"], ["a@acme.com", "b@evil.com"], False),
    ("domain_in", ["*.acme.com"], "bob@mail.acme.com", True), ("domain_in", ["acme.com"], "bob@mail.acme.com", False),
    ("domain_in", ["acme.com"], "Bob <bob@Acme.COM>", True), ("domain_in", ["acme.com"], "bob@acme.com.evil.io", False),
    ("domain_in", ["acme.com"], "not-an-address", False), ("domain_in", ["acme.com"], "a@acme.com, b@evil.com", False),
    ("domain_in", ["acme.com"], "https://acme.com/path", True), ("domain_in", ["acme.com"], "https://acme.com@evil.com/", False),
    ("not_domain_in", ["acme.com"], "bob@evil.com", True), ("not_domain_in", ["acme.com"], "bob@acme.com", False),
    ("not_domain_in", ["acme.com"], ["a@acme.com", "b@evil.com"], True),
    ("not_domain_in", ["acme.com"], "garbage", True),
    ("exists", True, "anything", True), ("exists", False, "anything", False),
])
def test_operator_truth_table(op, value, arg, expected):
    p = cond(op, value)
    assert (ev(p, "t", {"a": arg}).decision is Decision.allow) is expected, (op, value, arg)


def test_missing_and_null_arguments():
    assert ev(cond("in", ["a"]), "t", {}).rule_id == DEFAULT_DENY                       # allow rule: no arg -> no match
    assert ev(cond("eq", "x"), "t", {"a": None}).rule_id == DEFAULT_DENY
    assert ev(cond("not_in", ["a"], effect="block"), "t", {}).decision is Decision.block   # negated block rule fires
    assert ev(cond("not_domain_in", ["acme.com"], effect="block"), "t", {}).decision is Decision.block
    assert ev(cond("exists", False), "t", {}).decision is Decision.allow
    assert ev(cond("ne", "x", effect="block"), "t", {}).decision is Decision.block


def test_dotted_and_indexed_paths():
    p = pol("  - {id: r, effect: allow, tool: t, when: {arg: 'payload.to.0', op: domain_in, value: [acme.com]}}")
    assert ev(p, "t", {"payload": {"to": ["a@acme.com"]}}).decision is Decision.allow
    assert ev(p, "t", {"payload": {"to": ["a@evil.com"]}}).rule_id == DEFAULT_DENY
    assert ev(p, "t", {"payload": {"to": []}}).rule_id == DEFAULT_DENY
    assert ev(p, "t", {"payload": "str"}).rule_id == DEFAULT_DENY
    assert ev(p, "t", {"payload.to.0": "a@acme.com"}).rule_id == DEFAULT_DENY            # literal dotted key is not a path


def test_scope_operators():
    assert ev(SAMPLE, "read_email", {"folder": "Invoices"}).decision is Decision.allow
    assert ev(SAMPLE, "read_email", {"folder": "Secrets"}).rule_id == DEFAULT_DENY
    assert ev(SAMPLE, "read_email", {}).rule_id == DEFAULT_DENY
    p = pol("  - {id: r, effect: block, tool: t, when: {arg: folder, op: not_in_scope, value: mail_folders}}",
            "scopes: {mail_folders: [INBOX]}")
    assert ev(p, "t", {"folder": "Other"}).decision is Decision.block
    assert ev(p, "t", {"folder": "INBOX"}).rule_id == DEFAULT_DENY


def test_combinators():
    p = pol("  - id: r\n    effect: block\n    tool: t\n    when:\n      all:\n"
            "        - {arg: a, op: gt, value: 5}\n        - any:\n            - {arg: b, op: eq, value: x}\n"
            "            - not: {arg: c, op: in, value: [ok]}\n")
    assert ev(p, "t", {"a": 6, "b": "x", "c": "ok"}).decision is Decision.block
    assert ev(p, "t", {"a": 6, "b": "y", "c": "bad"}).decision is Decision.block
    assert ev(p, "t", {"a": 6, "b": "y", "c": "ok"}).rule_id == DEFAULT_DENY
    assert ev(p, "t", {"a": 1, "b": "x"}).rule_id == DEFAULT_DENY


def test_bare_list_condition_means_all():
    p = pol("  - id: r\n    effect: allow\n    tool: t\n    when:\n      - {arg: a, op: eq, value: 1}\n      - {arg: b, op: eq, value: 2}\n")
    assert ev(p, "t", {"a": 1, "b": 2}).decision is Decision.allow and ev(p, "t", {"a": 1}).rule_id == DEFAULT_DENY


# ── the arch scenarios ──────────────────────────────────────────────────────────────────────────
def test_external_send_is_blocked_with_the_rule_and_reason():
    r = ev(SAMPLE, "send_email", {"to": "x@unknown.com", "body": "..."})
    assert (r.decision, r.rule_id, r.reason) == (Decision.block, "deny-external-send",
                                                 "External email is not permitted for this agent")
    assert r.effect_tag is EffectTag.external


def test_internal_send_allowed_but_mixed_recipients_blocked():
    assert ev(SAMPLE, "send_email", {"to": "bob@acme.com"}).decision is Decision.allow
    assert ev(SAMPLE, "send_email", {"to": ["bob@acme.com", "x@unknown.com"]}).rule_id == "deny-external-send"
    assert ev(SAMPLE, "send_email", {"to": "bob@acme.com.evil.io"}).rule_id == "deny-external-send"
    assert ev(SAMPLE, "send_email", {}).rule_id == "deny-external-send"                 # no recipient at all: still blocked


def test_payments_small_large_and_unparsable():
    assert ev(SAMPLE, "pay_invoice", {"amount": 500}).decision is Decision.allow
    assert ev(SAMPLE, "pay_invoice", {"amount": 5000}).rule_id == "ask-large-payment"
    r = ev(SAMPLE, "pay_invoice", {"amount": "5,000"})        # neither rule matches -> financial tag default
    assert (r.decision, r.rule_id) == (Decision.ask, "tag-default:financial")
    assert ev(SAMPLE, "pay_invoice", {}).rule_id == "tag-default:financial"


def test_tag_defaults_fill_gaps_only():
    assert ev(SAMPLE, "delete_email", {"id": 1}).rule_id == "tag-default:destructive"
    assert ev(SAMPLE, "run_shell", {"cmd": "ls"}).decision is Decision.block
    assert ev(SAMPLE, "run_shell", {"cmd": "ls"}).rule_id == "tag-default:execute"
    # an advisory tag from the caller applies defaults to tools the policy doesn't know, never loosens known ones
    assert ev(SAMPLE, "mystery", {}, advised_tag=EffectTag.execute).rule_id == "tag-default:execute"
    assert ev(SAMPLE, "send_email", {"to": "x@evil.com"}, advised_tag=EffectTag.read).effect_tag is EffectTag.external


# ── arguments in odd shapes (OpenAI sends a JSON string) ────────────────────────────────────────
def test_string_arguments_are_parsed():
    assert ev(SAMPLE, "send_email", '{"to": "bob@acme.com"}').decision is Decision.allow
    assert ev(SAMPLE, "send_email", '{"to": "x@evil.com"}').rule_id == "deny-external-send"
    assert ev(SAMPLE, "pay_invoice", '{"amount": 5000}').rule_id == "ask-large-payment"


@pytest.mark.parametrize("raw", ["{not json", "[1, 2]", '"just a string"', "42", "null"])
def test_unparsable_or_non_object_arguments_never_raise_and_never_allow_by_accident(raw):
    r = ev(SAMPLE, "read_email", raw)
    assert r.decision is Decision.block and r.args_valid is False and "not valid JSON" in r.reason
    assert ev(SAMPLE, "send_email", raw).rule_id == "deny-external-send"


def test_none_and_empty_arguments_are_empty_objects():
    assert parse_args(None) == ({}, True, "{}") and parse_args("") == ({}, True, "{}") and parse_args("  ")[1]
    assert ev(parse_policy("version: 1\nrules:\n  - {id: a, effect: allow, tool: ping}\n"), "ping", None).decision is Decision.allow


def test_non_json_types_in_arguments_do_not_crash():
    r = ev(SAMPLE, "send_email", {"to": object(), "n": {1, 2}})
    assert r.decision is Decision.block


# ── human approval allowance ────────────────────────────────────────────────────────────────────
def test_approved_ask_becomes_allow_only_for_the_exact_call():
    args = {"amount": 5000, "payee": "ACME"}
    h = args_hash(args)
    approved = frozenset({("pay_invoice", h)})
    r = ev(SAMPLE, "pay_invoice", args, approved=approved)
    assert (r.decision, r.rule_id, r.approved_by_human) == (Decision.allow, "ask-large-payment", True)
    assert ev(SAMPLE, "pay_invoice", {"amount": 5001, "payee": "ACME"}, approved=approved).decision is Decision.ask
    assert ev(SAMPLE, "pay_invoice", args, approved=frozenset({("other_tool", h)})).decision is Decision.ask
    assert args_hash({"payee": "ACME", "amount": 5000}) == h                    # key order does not matter


def test_approval_never_overrides_a_block():
    args = {"to": "x@evil.com"}
    r = ev(SAMPLE, "send_email", args, approved=frozenset({("send_email", args_hash(args))}))
    assert r.decision is Decision.block


def test_approval_applies_to_tag_default_ask():
    args = {"id": 7}
    r = ev(SAMPLE, "delete_email", args, approved=frozenset({("delete_email", args_hash(args))}))
    assert r.decision is Decision.allow and r.approved_by_human


def test_high_risk_still_blocks_an_approved_call():
    args = {"amount": 5000}
    r = ev(SAMPLE, "pay_invoice", args, risk=0.9, approved=frozenset({("pay_invoice", args_hash(args))}))
    assert r.decision is Decision.block and r.rule_id == "tighten-on-risk"


# ── fail closed ─────────────────────────────────────────────────────────────────────────────────
CATASTROPHIC = "  - {id: r, effect: allow, tool: %s, when: {arg: a, op: regex, value: '(a|aa)+$'}}"


def test_regex_timeout_fails_closed_for_effectful_tools():
    p = pol(CATASTROPHIC % "send_email", "tools: {send_email: {effect_tag: external}}")
    r = ev(p, "send_email", {"a": "a" * 60 + "b"})
    assert (r.decision, r.rule_id) == (Decision.block, EVALUATOR_ERROR)


def test_regex_timeout_fails_open_for_read_tools_with_a_distinct_rule_id():
    p = pol(CATASTROPHIC % "lookup", "tools: {lookup: {effect_tag: read}}")
    r = ev(p, "lookup", {"a": "a" * 60 + "b"})
    assert (r.decision, r.rule_id) == (Decision.allow, f"{EVALUATOR_ERROR}-fail-open")


def test_oversized_arguments_fail_closed():
    assert ev(SAMPLE, "send_email", {"to": "x" * 1_100_000}).rule_id == EVALUATOR_ERROR


def test_evaluate_never_raises_on_hostile_input():
    for tool in ("", "a" * 10_000, "\x00", "../../etc/passwd", "ünïcödé"):
        for args in (None, {}, {"x": object()}, "💥", "{" * 1000, [], 3):
            evaluate(SAMPLE, tool, args)          # type: ignore[arg-type]


def test_evaluation_is_deterministic():
    a = ev(SAMPLE, "send_email", {"to": "x@evil.com"})
    assert a == ev(SAMPLE, "send_email", {"to": "x@evil.com"})
