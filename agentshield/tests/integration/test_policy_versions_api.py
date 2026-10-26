from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

SAMPLE = (Path(__file__).resolve().parent.parent / "fixtures" / "policies" / "email_reader.yaml").read_text()
SLUG = "email-reader-01"
URL = f"/v1/admin/agents/{SLUG}/policy/versions"


@pytest.fixture
async def acct(api):
    a = await api.signup()
    await a.make_agent(SLUG)
    return a


async def test_create_list_get_versions(acct):
    r = await acct.post(URL, {"yaml": SAMPLE})
    assert r.status_code == 201 and r.json()["version"] == 1 and r.json()["active"] is False
    assert len(r.json()["sha256"]) == 64
    r2 = await acct.post(URL, {"yaml": SAMPLE.replace("max_rpm: 60", "max_rpm: 30")})
    assert r2.json()["version"] == 2
    listed = (await acct.get(URL)).json()
    assert [v["version"] for v in listed] == [2, 1] and "yaml" not in listed[0] or listed[0]["yaml"] is None
    one = (await acct.get(f"{URL}/1")).json()
    assert one["yaml"] == SAMPLE and one["parsed"]["budgets"]["max_rpm"] == 60
    assert (await acct.get(f"{URL}/99")).status_code == 404


async def test_invalid_policy_returns_line_numbered_errors(acct):
    bad = "version: 1\nrules:\n  - id: r\n    effect: block\n    tool: x\n    when: { arg: body, op: contains, value: x }\n"
    r = await acct.post(URL, {"yaml": bad})
    assert r.status_code == 422 and r.json()["code"] == "policy_invalid"
    assert r.json()["errors"][0] == {"line": 6, "path": "rules[0].when.op",
                                     "message": r.json()["errors"][0]["message"]}
    assert "Line 6" in r.json()["detail"]
    assert (await acct.get(URL)).json() == []                      # nothing was saved


async def test_policy_for_another_agent_is_rejected(acct):
    r = await acct.post(URL, {"yaml": SAMPLE.replace("agent: email-reader-01", "agent: someone-else")})
    assert r.status_code == 422 and "someone-else" in r.json()["detail"]
    assert (await acct.post(URL, {"yaml": SAMPLE.replace("agent: email-reader-01\n", "")})).status_code == 201


async def test_versions_are_numbered_in_order_and_immutable(acct):
    await acct.post(URL, {"yaml": SAMPLE})
    assert (await acct.post(URL, {"yaml": SAMPLE, "version": 1})).status_code == 409    # already exists
    assert (await acct.post(URL, {"yaml": SAMPLE, "version": 5})).status_code == 409    # not the next number
    assert (await acct.post(URL, {"yaml": SAMPLE, "version": 2})).status_code == 201


async def test_activation_needs_if_match_and_updates_the_agent(acct):
    await acct.post(URL, {"yaml": SAMPLE})
    r = await acct.post(f"{URL}/1/activate")
    assert r.status_code == 428
    etag = (await acct.get(f"/v1/admin/agents/{SLUG}")).headers["etag"]
    assert (await acct.post(f"{URL}/1/activate", headers={"If-Match": 'W/"stale"'})).status_code == 412
    r = await acct.post(f"{URL}/1/activate", headers={"If-Match": etag})
    assert r.status_code == 200 and r.json()["active"] is True
    assert (await acct.get(f"/v1/admin/agents/{SLUG}")).json()["active_policy_version"] == 1
    assert [v["active"] for v in (await acct.get(URL)).json()] == [True]
    assert (await acct.post(f"{URL}/1/activate", headers={"If-Match": etag})).status_code == 412   # etag moved on


async def test_activate_unknown_version_is_404(acct):
    etag = (await acct.get(f"/v1/admin/agents/{SLUG}")).headers["etag"]
    assert (await acct.post(f"{URL}/7/activate", headers={"If-Match": etag})).status_code == 404


async def test_create_with_activate_flag(acct):
    r = await acct.post(URL, {"yaml": SAMPLE, "activate": True})
    assert r.status_code == 201 and r.json()["active"] is True
    assert (await acct.get(f"/v1/admin/agents/{SLUG}")).json()["active_policy_version"] == 1


async def test_activation_is_scoped_to_one_agent(acct):
    await acct.make_agent("other-agent")
    await acct.post(URL, {"yaml": SAMPLE, "activate": True})
    assert (await acct.get("/v1/admin/agents/other-agent")).json()["active_policy_version"] is None


async def test_roles_viewer_reads_admin_writes(api, acct):
    await acct.post(URL, {"yaml": SAMPLE})
    viewer = await api.add_user(acct, "viewer")
    analyst = await api.add_user(acct, "analyst")
    assert (await viewer.get(URL)).status_code == 200 and (await viewer.get(f"{URL}/1")).status_code == 200
    assert (await viewer.post(URL, {"yaml": SAMPLE})).status_code == 403
    assert (await analyst.post(URL, {"yaml": SAMPLE})).status_code == 403
    assert (await viewer.post(f"{URL}/1/activate")).status_code == 403


async def test_unknown_agent_is_404(acct):
    assert (await acct.get("/v1/admin/agents/ghost/policy/versions")).status_code == 404
    assert (await acct.post("/v1/admin/agents/ghost/policy/versions", {"yaml": SAMPLE})).status_code == 404


async def test_oversized_yaml_field_is_rejected(acct):
    assert (await acct.post(URL, {"yaml": "x" * 300_001})).status_code == 422
