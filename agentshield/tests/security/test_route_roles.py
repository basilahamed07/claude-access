"""Every control-plane route declares a role; data-plane credentials never work there (OWASP API5)."""

import pytest
from tests.conftest import api_routes

pytestmark = [pytest.mark.integration, pytest.mark.security]

PUBLIC_CONTROL = {"/v1/signup", "/v1/auth/login", "/v1/auth/logout", "/healthz", "/readyz", "/metrics"}
DATA_PLANE = {"/v1/token"}   # authenticated by agent key, not user roles


def _required_role(route):
    def walk(dep):
        for d in dep.dependencies:
            role = getattr(d.call, "required_role", None)
            if role:
                return role
            found = walk(d)
            if found:
                return found
        return None
    return walk(route.dependant)


def _is_agent_auth(route):
    def walk(dep):
        for d in dep.dependencies:
            if getattr(d.call, "__name__", "") in {"agent_ctx", "agent_key_ctx"}:
                return True
            if walk(d):
                return True
        return False
    return walk(route.dependant)


def test_every_admin_route_declares_a_role(app):
    missing = [f"{sorted(r.methods)} {r.path}" for r in api_routes(app)
               if r.path.startswith("/v1/admin") and _required_role(r) is None]
    assert missing == []


def test_every_route_is_classified(app):
    unclassified = [f"{sorted(r.methods)} {r.path}" for r in api_routes(app)
                    if r.path not in PUBLIC_CONTROL and r.path not in DATA_PLANE
                    and not r.path.startswith("/v1/admin") and r.path != "/v1/auth/me"
                    and not _is_agent_auth(r) and not r.path.startswith(("/openapi", "/docs"))]
    assert unclassified == []


def test_mutating_admin_routes_require_at_least_analyst(app):
    weak = [f"{sorted(r.methods)} {r.path}" for r in api_routes(app)
            if r.path.startswith("/v1/admin") and (r.methods & {"POST", "PATCH", "DELETE", "PUT"})
            and _required_role(r) == "viewer"]
    assert weak == []


async def test_viewer_gets_403_on_every_admin_only_route(api, app):
    admin = await api.signup()
    viewer = await api.add_user(admin, "viewer")
    for r in api_routes(app):
        if not r.path.startswith("/v1/admin") or _required_role(r) != "admin":
            continue
        path = r.path.replace("{slug}", "x").replace("{key_id}", "00000000-0000-0000-0000-000000000000") \
            .replace("{upstream_id}", "00000000-0000-0000-0000-000000000000") \
            .replace("{user_id}", "00000000-0000-0000-0000-000000000000")
        for method in r.methods - {"HEAD", "OPTIONS"}:
            resp = await viewer.client.request(method, path, json={}, headers=viewer.h)
            assert resp.status_code == 403, (method, r.path, resp.status_code)


async def test_user_token_cannot_be_an_agent_and_vice_versa(api):
    admin = await api.signup()
    await admin.make_agent()
    key = await admin.make_key()
    c = api.client()
    assert (await c.get("/v1/admin/agents", headers={"Authorization": f"Bearer {key['key']}"})).status_code == 401
    assert (await c.post("/v1/token", headers={"Authorization": "Bearer asu_" + "z" * 32})).status_code == 401
