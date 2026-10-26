from pathlib import Path

import pytest

from agentshield.contracts.decision import EffectTag
from agentshield.policy.conditions import domain_matches, extract_domains
from agentshield.policy.loader import MAX_POLICY_BYTES, PolicyError, parse_policy

SAMPLE = (Path(__file__).resolve().parent.parent / "fixtures" / "policies" / "email_reader.yaml").read_text()


def errors_of(text: str):
    with pytest.raises(PolicyError) as exc:
        parse_policy(text)
    return exc.value.errors


def test_arch_sample_policy_parses():
    p = parse_policy(SAMPLE)
    assert [r.doc.id for r in p.rules] == ["allow-read-mail", "deny-external-send", "allow-internal-send",
                                           "allow-small-payment", "ask-large-payment", "tighten-on-risk"]
    assert p.doc.budgets.max_rpm == 60 and p.doc.scopes["mail_folders"] == ["INBOX", "Invoices"]
    assert len(p.sha256) == 32 and p.doc.default == "deny"


def test_minimal_policy_and_empty_rules_are_valid():
    assert parse_policy("version: 1\n").rules == []


def test_tag_resolution_order():
    p = parse_policy(SAMPLE)
    assert p.tag_for("read_email") is EffectTag.read
    assert p.tag_for("run_shell") is EffectTag.execute             # glob in `tools:`
    assert p.tag_for("totally_unknown") is EffectTag.external      # nothing known -> safest non-blocking assumption
    assert p.tag_for("totally_unknown", advised=EffectTag.read) is EffectTag.read
    assert p.tag_for("pay_invoice", advised=EffectTag.read) is EffectTag.financial   # policy wins over the caller


def test_tag_from_a_matching_rule_when_not_in_tools():
    p = parse_policy("version: 1\nrules:\n  - {id: r1, effect: allow, tool: lookup_*, effect_tag: read}\n")
    assert p.tag_for("lookup_user") is EffectTag.read


def test_invalid_yaml_reports_line():
    errs = errors_of("version: 1\nrules:\n  - id: [unclosed\n")
    assert errs[0].line >= 2 and "invalid YAML" in errs[0].message


def test_not_a_mapping():
    assert "mapping" in errors_of("- just\n- a list\n")[0].message


def test_default_allow_is_rejected_with_line_number():
    errs = errors_of("version: 1\ndefault: allow\nrules: []\n")
    assert errs[0].line == 2 and errs[0].path == "default"


def test_unknown_top_level_and_rule_fields_are_rejected():
    errs = errors_of("version: 1\nsurprise: true\nrules:\n  - {id: a, effect: allow, tool: x, bogus: 1}\n")
    assert {e.path for e in errs} == {"surprise", "rules[0].bogus"}
    assert {e.line for e in errs} == {2, 4}


def test_wrong_version():
    assert errors_of("version: 2\n")[0].path == "version"


def test_duplicate_rule_ids_point_at_the_second():
    errs = errors_of("version: 1\nrules:\n  - {id: same, effect: allow, tool: a}\n  - {id: same, effect: block, tool: b}\n")
    assert errs[0].line == 4 and "duplicate rule id 'same'" in errs[0].message


def test_unknown_operator_has_path_and_line():
    errs = errors_of("version: 1\nrules:\n  - id: r\n    effect: block\n    tool: x\n"
                     "    when: { arg: body, op: contains, value: 'x' }\n")
    assert errs[0].line == 6 and errs[0].path == "rules[0].when.op" and "unknown operator 'contains'" in errs[0].message


def test_bad_regex_and_overlong_regex():
    base = "version: 1\nrules:\n  - id: r\n    effect: block\n    tool: x\n    when: {{ arg: a, op: regex, value: '{}' }}\n"
    assert "invalid regular expression" in errors_of(base.format("(unclosed"))[0].message
    assert "1-500" in errors_of(base.format("a" * 501))[0].message


def test_undefined_scope_reference():
    errs = errors_of("version: 1\nrules:\n  - id: r\n    effect: allow\n    tool: x\n"
                     "    when: { arg: folder, op: in_scope, value: nope }\n")
    assert "unknown scope 'nope'" in errs[0].message


def test_empty_scope_and_bad_values():
    assert errors_of("version: 1\nscopes: { a: [] }\n")[0].path == "scopes.a"
    assert "non-empty list" in errors_of("version: 1\nrules:\n  - {id: r, effect: allow, tool: x, when: {arg: a, op: in, value: []}}\n")[0].message
    assert "needs a number" in errors_of("version: 1\nrules:\n  - {id: r, effect: allow, tool: x, when: {arg: a, op: gt, value: abc}}\n")[0].message
    assert "exactly one" in errors_of("version: 1\nrules:\n  - {id: r, effect: allow, tool: x, when: {op: eq, value: 1}}\n")[0].message


def test_session_condition_rules():
    assert parse_policy("version: 1\nrules:\n  - {id: r, effect: block, tool: '*', when: {session: risk_score, op: gte, value: 0.5}}\n")
    assert "unknown session field" in errors_of("version: 1\nrules:\n  - {id: r, effect: block, tool: '*', when: {session: nope, op: gte, value: 1}}\n")[0].message
    assert "numeric operator" in errors_of("version: 1\nrules:\n  - {id: r, effect: block, tool: '*', when: {session: risk_score, op: eq, value: 1}}\n")[0].message


def test_combinators_compile_and_validate_children():
    ok = ("version: 1\nrules:\n  - id: r\n    effect: block\n    tool: x\n    when:\n      any:\n"
          "        - { arg: a, op: eq, value: 1 }\n        - not: { arg: b, op: in, value: [1, 2] }\n")
    assert parse_policy(ok)
    bad = ok.replace("op: in, value: [1, 2]", "op: nope, value: 1")
    assert errors_of(bad)[0].path == "rules[0].when.any[1].not.op"


def test_tag_defaults_can_only_ask_or_block():
    assert errors_of("version: 1\ntag_defaults: { read: allow }\n")
    assert parse_policy("version: 1\ntag_defaults: { financial: ask, execute: block }\n")
    assert errors_of("version: 1\ntag_defaults: { teleport: ask }\n")


def test_unknown_effect_and_tag():
    assert errors_of("version: 1\nrules:\n  - {id: r, effect: maybe, tool: x}\n")
    assert errors_of("version: 1\ntools:\n  x: { effect_tag: weird }\n")


def test_yaml_aliases_are_rejected():
    errs = errors_of("version: 1\nscopes:\n  a: &x [one]\n  b: *x\n")
    assert "aliases" in errs[0].message


def test_duplicate_yaml_keys_are_rejected():
    errs = errors_of("version: 1\nrules: []\nrules:\n  - {id: r, effect: allow, tool: x}\n")
    assert "duplicate key" in errs[0].message


def test_yaml_tags_cannot_construct_python_objects():
    errs = errors_of("version: 1\nscopes: !!python/object/apply:os.system ['id']\n")
    assert errs and "invalid YAML" in errs[0].message


def test_oversized_policy_is_rejected():
    assert "larger than" in errors_of("version: 1\n# " + "x" * (MAX_POLICY_BYTES + 1))[0].message


def test_rule_ids_must_be_slug_like():
    assert errors_of("version: 1\nrules:\n  - {id: 'Bad Id!', effect: allow, tool: x}\n")


# ── domain helpers ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(("value", "expected"), [
    ("bob@acme.com", ["acme.com"]),
    ("Bob <BOB@Acme.com>", ["acme.com"]),
    ("a@x.com, b@y.org;c@z.net", ["x.com", "y.org", "z.net"]),
    (["a@x.com", "b@y.org"], ["x.com", "y.org"]),
    ("https://user:pw@evil.example/path?q=1", ["evil.example"]),
    ("evil.example", ["evil.example"]),
    ("not-an-address", [None]),
    ("", [None]),
    (42, [None]),
    (["a@x.com", 7], ["x.com", None]),
])
def test_extract_domains(value, expected):
    assert extract_domains(value) == expected


def test_domain_matches_exact_and_wildcard():
    assert domain_matches("acme.com", "acme.com")
    assert not domain_matches("mail.acme.com", "acme.com")
    assert domain_matches("mail.acme.com", "*.acme.com")
    assert not domain_matches("acme.com", "*.acme.com")
    assert not domain_matches("evilacme.com", "*.acme.com")
    assert not domain_matches("acme.com.evil.io", "acme.com")
