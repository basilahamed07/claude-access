"""RFC 9457 problem details with the stable error codes of api §A.5."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, model_validator

ERROR_BASE = "https://agentshield.dev/errors"

STATUS_BY_CODE: dict[str, int] = {
    "unauthenticated": 401, "forbidden": 403, "credential_mismatch": 403, "not_found": 404,
    "conflict": 409, "idempotency_conflict": 409, "precondition_failed": 412,
    "precondition_required": 428, "payload_too_large": 413, "validation_failed": 422,
    "policy_invalid": 422, "rate_limited": 429, "budget_exceeded": 429, "upstream_error": 502,
    "upstream_timeout": 504, "internal": 500,
}


class Problem(BaseModel):
    type: str = ""
    title: str
    status: int
    code: str
    detail: str | None = None
    instance: str | None = None
    request_id: str | None = None
    errors: list[dict[str, Any]] | None = None

    @model_validator(mode="after")
    def _default_type(self) -> Problem:
        if not self.type:
            self.type = f"{ERROR_BASE}/{self.code}"
        return self


class ApiError(Exception):
    """Raised anywhere in the control/data plane; rendered as application/problem+json."""

    def __init__(self, code: str, detail: str | None = None, *, title: str | None = None,
                 errors: list[dict[str, Any]] | None = None,
                 headers: dict[str, str] | None = None, status: int | None = None) -> None:
        super().__init__(detail or code)
        self.code = code
        self.status = status or STATUS_BY_CODE[code]
        self.title = title or code.replace("_", " ").capitalize()
        self.detail = detail
        self.errors = errors
        self.headers = headers or {}
