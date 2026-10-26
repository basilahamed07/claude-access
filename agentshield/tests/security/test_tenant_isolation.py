"""Tenant B's resource ids, used with tenant A's credentials, must behave as if they do not exist."""

import uuid

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.security]


@pytest.fixture
async def world(api):
    a, b = await api.signup(), await api.signup()
    await b.make_agent("b-agent")
    key_b = await b.make_key("b-agent")
    up_b = await b.make_upstream("b-up")
    users_b = (await b.get("/v1/admin/users")).json()["items"]
    return a, b, {"key_id": key_b["id"], "upstream_id": up_b["id"], "user_id": users_b[0]["id"], "slug": "b-agent"}


ROUTES = [
    ("GET", "/v1/admin/agents/{slug}", None),
    ("PATCH", "/v1/admin/agents/{slug}", {"name": "pwned"}),
    ("GET", "/v1/admin/agents/{slug}/keys", None),
    ("POST", "/v1/admin/agents/{slug}/keys", {}),
    ("POST", "/v1/admin/agents/{slug}/keys/{key_id}/revoke", {}),
    ("POST", "/v1/admin/agents/{slug}/keys/{key_id}/rotate", {"overlap_seconds": 0}),
    ("GET", "/v1/admin/agents/{slug}/snippet", None),
    ("GET", "/v1/admin/upstreams/{upstream_id}", None),
    ("PATCH", "/v1/admin/upstreams/{upstream_id}", {"name": "pwned"}),
    ("DELETE", "/v1/admin/upstreams/{upstream_id}", None),
    ("PATCH", "/v1/admin/users/{user_id}", {"role": "viewer"}),
    ("GET", "/v1/admin/agents/{slug}/policy/versions", None),
    ("POST", "/v1/admin/agents/{slug}/policy/versions", {"yaml": "version: 1\n"}),
    ("GET", "/v1/admin/agents/{slug}/policy/versions/1", None),
    ("POST", "/v1/admin/agents/{slug}/policy/versions/1/activate", {}),
]


@pytest.mark.parametrize(("method", "path", "body"), ROUTES, ids=[f"{m} {p}" for m, p, _ in ROUTES])
async def test_foreign_ids_return_404(world, method, path, body):
    a, b, ids = world
    url = path.format(**ids)
    headers = {"If-Match": "*"} if ("agents" in path and method in {"PATCH", "POST"}) else {}
    r = await a.client.request(method, url, json=body, headers={**a.h, **headers})
    assert r.status_code == 404, (url, r.status_code, r.text)
    # and the victim's data is untouched
    assert (await b.get(f"/v1/admin/agents/{ids['slug']}")).json()["name"] != "pwned"


async def test_lists_only_show_own_rows(world):
    a, b, _ = world
    await a.make_agent("a-agent")
    slugs = {x["slug"] for x in (await a.get("/v1/admin/agents")).json()["items"]}
    assert slugs == {"a-agent"}
    assert (await a.get("/v1/admin/upstreams")).json() == []
    emails = {u["email"] for u in (await a.get("/v1/admin/users")).json()["items"]}
    assert emails == {a.email}


@pytest.mark.parametrize("field", ["tenant_id", "tenant", "tenantId"])
async def test_tenant_id_in_body_is_rejected(world, field):
    a, b, _ = world
    r = await a.post("/v1/admin/agents", {"slug": "x-agent", "name": "n", "owner": "o", field: b.tenant_id})
    assert r.status_code == 422


async def test_tenant_id_in_query_does_not_switch_tenant(world):
    a, b, ids = world
    r = await a.get(f"/v1/admin/agents/{ids['slug']}?tenant_id={b.tenant_id}")
    assert r.status_code == 404


async def test_same_slug_in_two_tenants_is_independent(api):
    a, b = await api.signup(), await api.signup()
    await a.make_agent("shared")
    await b.make_agent("shared")
    ka, kb = await a.make_key("shared"), await b.make_key("shared")
    # each key authenticates as its own tenant only
    ta = (await api.client().post("/v1/token", headers={"Authorization": f"Bearer {ka['key']}"})).json()
    tb = (await api.client().post("/v1/token", headers={"Authorization": f"Bearer {kb['key']}"})).json()
    import jwt
    ca = jwt.decode(ta["access_token"], options={"verify_signature": False})
    cb = jwt.decode(tb["access_token"], options={"verify_signature": False})
    assert ca["tid"] == a.tenant_id and cb["tid"] == b.tenant_id and ca["tid"] != cb["tid"]


async def test_random_uuid_is_404_not_500(world):
    a, _, _ = world
    rid = uuid.uuid4()
    assert (await a.client.get(f"/v1/admin/upstreams/{rid}")).status_code == 404
    assert (await a.client.get("/v1/admin/upstreams/not-a-uuid")).status_code == 422
