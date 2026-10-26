"""The attack demo against a real stack: gateway + audit worker + Postgres + Redis + a scripted, hijackable model provider.

Needs AGENTSHIELD_TEST_DSN and AGENTSHIELD_TEST_REDIS (run `agentshield/scripts/dev-services.sh`).
"""

from __future__ import annotations

import ast
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from demo.email_agent import agent, mailbox, profiles, runner
from demo.email_agent.setup_demo import EMAIL, PASSWORD, setup

ROOT = Path(__file__).resolve().parents[3]
DSN, REDIS = os.environ.get("AGENTSHIELD_TEST_DSN"), os.environ.get("AGENTSHIELD_TEST_REDIS")
pytestmark = pytest.mark.skipif(not (DSN and REDIS), reason="set AGENTSHIELD_TEST_DSN and AGENTSHIELD_TEST_REDIS")
PY = str(ROOT / "agentshield" / ".venv" / "bin" / "python")
PY = PY if Path(PY).exists() else sys.executable


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_for(url: str, proc: subprocess.Popen[bytes], seconds: float = 90) -> None:
    end = time.time() + seconds
    while time.time() < end:
        if proc.poll() is not None:
            raise RuntimeError(f"process for {url} exited with {proc.returncode}")
        try:
            if httpx.get(url, timeout=1).status_code < 500:
                return
        except httpx.HTTPError:
            time.sleep(0.3)
    raise TimeoutError(url)


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    api_port, stub_port = free_port(), free_port()
    env = {**os.environ, "PORT": str(api_port), "STACK_DB": f"demo_{secrets.token_hex(4)}", "AGENTSHIELD_ALLOW_PRIVATE_UPSTREAMS": "127.0.0.1",
           "AGENTSHIELD_TEST_REDIS": REDIS.rsplit("/", 1)[0] + "/4", "PY": PY}
    gateway = subprocess.Popen([str(ROOT / "agentshield" / "scripts" / "run_stack.sh")], env=env, cwd=ROOT / "agentshield", stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    stub = subprocess.Popen([PY, "-m", "uvicorn", "demo.email_agent.stub_server:app", "--port", str(stub_port), "--log-level", "warning"], cwd=ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env={**os.environ, "PYTHONPATH": str(ROOT)})
    try:
        wait_for(f"http://127.0.0.1:{api_port}/healthz", gateway)
        wait_for(f"http://127.0.0.1:{stub_port}/docs", stub)
        out = setup(f"http://127.0.0.1:{api_port}", f"http://127.0.0.1:{stub_port}/v1")
        yield {"gateway": f"http://127.0.0.1:{api_port}", "stub": f"http://127.0.0.1:{stub_port}", **out}
    finally:
        for p in (gateway, stub):
            p.terminate()
        for p in (gateway, stub):
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()


@pytest.fixture
def env(stack, tmp_path, monkeypatch):
    monkeypatch.setenv("DEMO_OUTBOX", str(tmp_path / "outbox.jsonl"))
    monkeypatch.setenv("DEMO_UNPROTECTED_BASE_URL", f"{stack['stub']}/v1")
    monkeypatch.setenv("DEMO_PROTECTED_BASE_URL", stack["DEMO_PROTECTED_BASE_URL"])
    monkeypatch.setenv("DEMO_PROTECTED_API_KEY", stack["DEMO_PROTECTED_API_KEY"])
    mailbox.reset_outbox()
    return stack


def dashboard_events(stack, session_key: str, want: int = 4) -> tuple[list[dict], dict]:
    c = httpx.Client(base_url=stack["gateway"], timeout=20)
    c.post("/v1/auth/login", json={"email": EMAIL, "password": PASSWORD}).raise_for_status()
    for _ in range(60):
        sessions = c.get("/v1/admin/sessions?agent=email-reader-01").json()["items"]
        if sessions:
            sid = sessions[0]["id"]
            events = c.get(f"/v1/admin/events?session={sid}&include_payload=true&limit=200").json()["items"]
            if len(events) >= want:
                return list(reversed(events)), c.get(f"/v1/admin/sessions/{sid}/export.json").json()
        time.sleep(0.5)
    raise AssertionError("audit events never arrived")


def test_unprotected_run_leaks_the_invoices(env):
    t = agent.run(env=profiles.resolve("unprotected"))
    outbox = mailbox.read_outbox()
    assert [m["to"] for m in outbox] == ["x@unknown.com"]
    assert any(c["name"] == "send_email" for c in t.tool_calls)
    assert "forwarded" in t.final_reply.lower()


def test_protected_run_blocks_the_leak_and_leaves_a_verified_trail(env):
    t = agent.run(env=profiles.resolve("protected"))
    assert mailbox.read_outbox() == []
    assert "Action blocked by AgentShield" in t.final_reply and "deny-external-send" in t.final_reply
    events, export = dashboard_events(env, t.session)
    scanned = [e for e in events if e["type"] == "content.scanned"]
    decisions = [e for e in events if e["type"] == "policy.decision" and e["decision"] == "block"]
    assert scanned and scanned[0]["payload"]["verdict"] == "malicious" and scanned[0]["severity"] == "high"
    assert decisions and decisions[0]["rule_id"] in {"deny-external-send", "tighten-on-risk"}
    assert export["verification"]["verified"] is True


def test_the_two_runs_differ_only_in_connection_settings():
    a, b = profiles.resolve("unprotected", {}), profiles.resolve("protected", {})
    assert set(a) == set(b)
    assert {k for k in a if a[k] != b[k]} == {"OPENAI_BASE_URL", "OPENAI_API_KEY"}
    scripts = {n: ast.dump(ast.parse((ROOT / "demo" / "email_agent" / f"run_{n}.py").read_text())) for n in ("unprotected", "protected")}
    assert scripts["unprotected"].replace("unprotected", "X") == scripts["protected"].replace("protected", "X")


def test_running_it_twice_gives_the_same_result(env, capsys):
    results = []
    for _ in range(2):
        assert runner.main("protected") == 0
        results.append((mailbox.read_outbox(), "nothing left the company" in capsys.readouterr().out))
    assert results == [([], True), ([], True)]
    assert runner.main("unprotected") == 0 and runner.main("unprotected") == 0
    assert [m["to"] for m in mailbox.read_outbox()] == ["x@unknown.com"]          # reset between runs: one mail, not two


def test_with_the_default_setting_the_scanner_removes_the_attack_before_the_model_sees_it(env):
    c = httpx.Client(base_url=env["gateway"], timeout=20)
    login = c.post("/v1/auth/login", json={"email": EMAIL, "password": PASSWORD}).json()
    h = {"X-CSRF-Token": login["csrf_token"]}
    s = c.get("/v1/admin/settings")
    c.patch("/v1/admin/settings", json={"on_malicious": "sanitize"}, headers={**h, "If-Match": s.headers["etag"]}).raise_for_status()
    try:
        t = agent.run(env=profiles.resolve("protected"))
    finally:
        s = c.get("/v1/admin/settings")
        c.patch("/v1/admin/settings", json={"on_malicious": "flag"}, headers={**h, "If-Match": s.headers["etag"]}).raise_for_status()
    assert mailbox.read_outbox() == [] and "Action blocked" not in t.final_reply and not any(x["name"] == "send_email" for x in t.tool_calls)


def test_missing_key_is_explained(monkeypatch, capsys):
    monkeypatch.delenv("DEMO_PROTECTED_API_KEY", raising=False)
    monkeypatch.setattr(runner, "ENV_FILE", Path("/nonexistent"))
    assert runner.main("protected") == 2 and "make demo" in capsys.readouterr().err
