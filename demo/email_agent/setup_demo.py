"""Create (or reuse) the demo tenant on a running AgentShield: provider, agent, policy, key.

Idempotent. Prints the dashboard login and writes `.env.protected` (OPENAI_BASE_URL / OPENAI_API_KEY for the protected run).
The tenant is set to `on_malicious: flag` on purpose: the scanner raises the alarm but still passes the text on, so you can watch
the permission layer stop the hijacked agent. Switch it to `sanitize` in Settings to watch the scanner remove the attack instead.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path
from typing import Any

import httpx

HERE = Path(__file__).resolve().parent
EMAIL = os.environ.get("DEMO_ADMIN_EMAIL", "demo-admin@example.com")
AGENT = "email-reader-01"
SECRET_FILE = HERE / ".demo-admin-password"


def admin_password() -> str:
    """No built-in password: use DEMO_ADMIN_PASSWORD, else the one generated on the first run (kept in a 0600 file), else make one."""
    if os.environ.get("DEMO_ADMIN_PASSWORD"):
        return os.environ["DEMO_ADMIN_PASSWORD"]
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text(encoding="utf-8").strip()
    pw = secrets.token_urlsafe(18)
    fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(pw + "\n")
    return pw


def setup(gateway: str, upstream_url: str, *, client: httpx.Client | None = None, password: str | None = None) -> dict[str, str]:
    password = password or admin_password()
    http = client or httpx.Client(base_url=gateway, timeout=30)
    r = http.post("/v1/signup", json={"tenant_name": "Demo Runner", "email": EMAIL, "password": password})
    if r.status_code not in (201, 409, 422):
        r.raise_for_status()
    login = http.post("/v1/auth/login", json={"email": EMAIL, "password": password})
    if login.status_code != 200:
        raise SystemExit(f"Could not sign in as {EMAIL} ({login.status_code}). If the demo tenant was made with another password, set DEMO_ADMIN_PASSWORD.")
    h = {"X-CSRF-Token": login.json()["csrf_token"]}

    def call(method: str, path: str, **kw: Any) -> httpx.Response:
        return http.request(method, path, headers={**h, **kw.pop("headers", {})}, **kw)

    ups = call("GET", "/v1/admin/upstreams").json()
    up = next((u for u in ups if u["name"] == "demo-provider"), None)
    if up is None:
        up = call("POST", "/v1/admin/upstreams", json={
            "name": "demo-provider", "kind": "openai", "base_url": upstream_url, "api_key": "sk-demo-not-a-real-key",
            "model_map": {"gpt-4.1": {"model": "gpt-4.1", "input_micro_usd_per_mtok": 2_000_000, "output_micro_usd_per_mtok": 8_000_000}}}).raise_for_status().json()
    agent = call("GET", f"/v1/admin/agents/{AGENT}")
    if agent.status_code == 404:
        agent = call("POST", "/v1/admin/agents", json={"slug": AGENT, "name": "Email reader", "owner": "ops@acme.com", "purpose": "Summarises the inbox",
                                                       "risk_tier": "medium", "mode": "enforce", "upstream_id": up["id"]}).raise_for_status()
    elif agent.json()["mode"] != "enforce":      # new agents start in monitor mode (log what would be blocked); the demo needs enforcement
        call("PATCH", f"/v1/admin/agents/{AGENT}", headers={"If-Match": agent.headers["etag"]}, json={"mode": "enforce"}).raise_for_status()
    yaml_text = (HERE / "policy.yaml").read_text(encoding="utf-8")
    versions = call("GET", f"/v1/admin/agents/{AGENT}/policy/versions").json()
    active = next((v for v in versions if v["active"]), None)
    current = call("GET", f"/v1/admin/agents/{AGENT}/policy/versions/{active['version']}").json()["yaml"] if active else None
    if current != yaml_text:
        v = call("POST", f"/v1/admin/agents/{AGENT}/policy/versions", json={"yaml": yaml_text}).raise_for_status().json()
        etag = call("GET", f"/v1/admin/agents/{AGENT}").headers["etag"]
        call("POST", f"/v1/admin/agents/{AGENT}/policy/versions/{v['version']}/activate", headers={"If-Match": etag}, json={}).raise_for_status()
    settings = call("GET", "/v1/admin/settings")
    if settings.json().get("on_malicious") != "flag":
        call("PATCH", "/v1/admin/settings", headers={"If-Match": settings.headers["etag"]}, json={"on_malicious": "flag"}).raise_for_status()
    key = call("POST", f"/v1/admin/agents/{AGENT}/keys", json={}).raise_for_status().json()["key"]
    return {"DEMO_PROTECTED_BASE_URL": f"{gateway.rstrip('/')}/v1", "DEMO_PROTECTED_API_KEY": key, "DASHBOARD_LOGIN": EMAIL, "DASHBOARD_PASSWORD": password}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gateway", default=os.environ.get("DEMO_GATEWAY", "http://127.0.0.1:8000"))
    ap.add_argument("--upstream", default=os.environ.get("DEMO_UPSTREAM_URL", "http://127.0.0.1:9100/v1"))
    ap.add_argument("--dashboard", default=os.environ.get("DEMO_DASHBOARD", "http://127.0.0.1:5173"))
    a = ap.parse_args()
    out = setup(a.gateway, a.upstream)
    target = HERE / ".env.protected"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("".join(f"{k}={v}\n" for k, v in out.items() if k.startswith("DEMO_")))
    os.chmod(target, 0o600)
    print(f"Demo ready. Dashboard {a.dashboard}\n  login:    {out['DASHBOARD_LOGIN']}\n  password: {out['DASHBOARD_PASSWORD']}   (generated; kept in {SECRET_FILE.name}, mode 600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
