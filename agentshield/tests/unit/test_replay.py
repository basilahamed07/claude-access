"""replay_calls: re-evaluating recorded tool calls against a policy version (pure part of B17)."""

from datetime import UTC, datetime
from pathlib import Path

from agentshield.audit.replay import RecordedCall, _tool_from_summary, replay_calls
from agentshield.policy.loader import parse_policy

BASE = (Path(__file__).resolve().parents[1] / "fixtures" / "policies" / "email_reader.yaml").read_text()
NOW = datetime(2026, 10, 26, tzinfo=UTC)


def call(tool, args, decision, rule, *, tag="external", risk=0.0, approved=False, has_args=True, seq=1):
    return RecordedCall(seq=seq, ts=NOW, trace_id="t-1", session_id=None, tool=tool, arguments=args,
                        has_arguments=has_args, effect_tag=tag, decision=decision, rule_id=rule, risk=risk,
                        approved=approved, args_hash="h1" if approved else None)


def test_the_policy_that_made_the_decisions_reproduces_them():
    policy = parse_policy(BASE)
    calls = [call("read_email", {"folder": "INBOX"}, "allow", "allow-read-mail", tag="read"),
             call("send_email", {"to": "x@unknown.com"}, "block", "deny-external-send", seq=2),
             call("pay_invoice", {"amount": 5000}, "ask", "ask-large-payment", tag="financial", seq=3)]
    steps = replay_calls(policy, calls)
    assert [s.changed for s in steps] == [False, False, False]
    assert [s.replay_rule for s in steps] == ["allow-read-mail", "deny-external-send", "ask-large-payment"]


def test_a_relaxed_policy_changes_exactly_the_affected_step():
    relaxed = BASE.replace("""  - id: deny-external-send
    effect: block
    tool: send_email
    when: { arg: to, op: not_domain_in, value: ["acme.com"] }
    reason: "External email is not permitted for this agent"
""", "  - id: allow-any-send\n    effect: allow\n    tool: send_email\n")
    assert relaxed != BASE
    steps = replay_calls(parse_policy(relaxed), [call("read_email", {"folder": "INBOX"}, "allow", "allow-read-mail", tag="read"),
                                                 call("send_email", {"to": "x@unknown.com"}, "block", "deny-external-send", seq=2)])
    assert [s.changed for s in steps] == [False, True]
    assert (steps[1].recorded_decision, steps[1].replay_decision, steps[1].replay_rule) == ("block", "allow", "allow-any-send")


def test_recorded_risk_is_used_so_a_risk_rule_replays_the_same():
    steps = replay_calls(parse_policy(BASE), [call("read_email", {"folder": "INBOX"}, "block", "tighten-on-risk", tag="read", risk=0.9)])
    assert steps[0].replay_rule == "tighten-on-risk" and not steps[0].changed


def test_monitor_mode_calls_compare_against_what_would_have_happened():
    # recorded as allow in monitor mode, but would_have was "block": `calls` already carries would_have as the decision
    steps = replay_calls(parse_policy(BASE), [call("send_email", {"to": "x@unknown.com"}, "block", "deny-external-send")])
    assert not steps[0].changed


def test_human_approval_is_honoured_on_replay():
    args = {"vendor": "Initech", "amount": 5000}
    c = call("pay_invoice", args, "allow", "ask-large-payment", tag="financial", approved=True)
    from agentshield.policy.evaluator import args_hash
    c.args_hash = args_hash(args)
    assert replay_calls(parse_policy(BASE), [c])[0].replay_decision == "allow"


def test_calls_without_arguments_are_skipped_not_guessed():
    (step,) = replay_calls(parse_policy(BASE), [call("send_email", None, "block", "deny-external-send", has_args=False)])
    assert step.skipped == "payload_purged_or_truncated" and step.replay_decision is None and not step.changed


def test_unknown_effect_tag_text_is_ignored_safely():
    (step,) = replay_calls(parse_policy(BASE), [call("mystery", {}, "block", "default-deny", tag="bogus")])
    assert step.replay_decision == "block"


def test_tool_name_can_be_recovered_from_the_summary_when_the_payload_is_gone():
    assert _tool_from_summary("send_email requested (external)") == "send_email"
    assert _tool_from_summary("something else") == "?"
