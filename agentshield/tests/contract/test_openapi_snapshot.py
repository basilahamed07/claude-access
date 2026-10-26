"""The committed OpenAPI file is the API inventory (OWASP API9): it must match the code, and every route must be in it."""

import json
from pathlib import Path

from agentshield.gateway.app import create_app
from agentshield.settings import Settings

SPEC = Path(__file__).resolve().parents[2] / "openapi.json"


def test_snapshot_matches_the_generated_spec():
    generated = create_app(Settings(env="dev")).openapi()
    committed = json.loads(SPEC.read_text())
    assert committed == generated, "API changed: run `python scripts/export_openapi.py` and commit openapi.json"


def test_spec_is_stable_across_settings():
    assert create_app(Settings(env="prod")).openapi() == create_app(Settings(env="dev")).openapi()


def test_operation_ids_are_unique_and_metrics_is_not_published():
    spec = json.loads(SPEC.read_text())
    ops = [(p, m, o) for p, item in spec["paths"].items() for m, o in item.items() if m in {"get", "post", "patch", "delete", "put"}]
    assert len(ops) > 50
    ids = [o["operationId"] for _, _, o in ops]
    assert len(ids) == len(set(ids))
    assert "/metrics" not in spec["paths"]                       # internal only, deliberately undocumented


def test_new_b17_routes_are_in_the_contract():
    paths = json.loads(SPEC.read_text())["paths"]
    for p in ("/v1/admin/sessions", "/v1/admin/sessions/{session_id}/timeline", "/v1/admin/sessions/{session_id}/replay",
              "/v1/admin/sessions/{session_id}/export.json", "/v1/admin/agents/{slug}/policy/simulate",
              "/v1/admin/incidents", "/v1/admin/alerts", "/v1/admin/stats/overview", "/v1/scan", "/v1/check"):
        assert p in paths, p
