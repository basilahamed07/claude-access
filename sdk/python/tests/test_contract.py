"""The SDK's models must keep matching the committed OpenAPI contract."""

import json
from pathlib import Path

import pytest
from agentshield_sdk import models

SPEC = Path(__file__).resolve().parents[3] / "agentshield" / "openapi.json"
pytestmark = pytest.mark.skipif(not SPEC.exists(), reason="openapi.json not found (SDK tested outside the monorepo)")


def fields(name):
    return set(json.loads(SPEC.read_text())["components"]["schemas"][name]["properties"])


@pytest.mark.parametrize(("sdk", "api"), [(models.CheckResponse, "CheckResponse"), (models.ScanResult, "ScanResult"), (models.ScanFinding, "ScanFinding"),
                                          (models.Approval, "AgentApprovalRead")])
def test_response_models_cover_every_field_the_api_returns(sdk, api):
    missing = fields(api) - set(sdk.model_fields)
    assert missing == set(), f"{api} gained fields the SDK does not know: {missing}"


def test_request_shape_matches_the_check_request_schema():
    spec = json.loads(SPEC.read_text())["components"]["schemas"]
    sent = {"agent_id", "tenant", "session_id", "action", "context", "wait_seconds"}
    assert set(spec["CheckRequest"]["properties"]) == sent
    assert set(spec["Action"]["properties"]) == {"tool", "arguments", "effect_tag"}
    assert set(spec["CheckContext"]["properties"]) == {"user_request", "end_user", "untrusted_inputs"}
    assert set(spec["UntrustedInput"]["properties"]) == {"source", "id", "text"}
