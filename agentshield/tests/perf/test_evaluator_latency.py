"""Latency of the policy evaluator (arch §3 target: p95 < 20 ms). Prints the measured values."""

import random
import statistics
import time

import pytest

from agentshield.policy.evaluator import SessionState, evaluate
from agentshield.policy.loader import parse_policy

pytestmark = pytest.mark.perf


def big_policy(n_rules: int):
    rules = []
    for i in range(n_rules):
        tool = f"tool_{i % 40}" if i % 5 else f"glob_{i % 7}_*"
        rules.append(f"  - id: rule-{i}\n    effect: {['allow', 'block', 'ask'][i % 3]}\n    tool: '{tool}'\n"
                     f"    when: {{ all: [ {{arg: to, op: domain_in, value: [acme.com, '*.corp.acme.com']}},"
                     f" {{arg: amount, op: lte, value: {i * 10}}}, {{arg: path, op: regex, value: '^/data/[a-z]+/{i}$'}} ] }}")
    return parse_policy("version: 1\nrules:\n" + "\n".join(rules) + "\n")


def test_evaluator_p95_under_20ms_for_a_large_policy():
    policy = big_policy(200)
    rnd = random.Random(7)
    calls = [(f"tool_{rnd.randrange(40)}" if rnd.random() < 0.8 else f"glob_{rnd.randrange(7)}_x",
              {"to": rnd.choice(["a@acme.com", "x@evil.com", "b@mail.corp.acme.com"]), "amount": rnd.randrange(3000),
               "path": f"/data/abc/{rnd.randrange(200)}"}) for _ in range(5000)]
    samples = []
    session = SessionState(0.1)
    for tool, args in calls:
        t = time.perf_counter()
        evaluate(policy, tool, args, session)
        samples.append((time.perf_counter() - t) * 1000)
    samples.sort()
    p50, p95, p99 = samples[len(samples) // 2], samples[int(len(samples) * 0.95)], samples[int(len(samples) * 0.99)]
    print(f"\nevaluator (200 rules, 5000 calls): p50={p50:.3f} ms  p95={p95:.3f} ms  p99={p99:.3f} ms  "
          f"mean={statistics.mean(samples):.3f} ms")
    assert p95 < 20
