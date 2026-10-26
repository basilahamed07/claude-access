"""RFC 9457 problem+json rendering for every non-proxy route (api spec §A.5)."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DBAPIError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from ..contracts.errors import STATUS_BY_CODE, ApiError, Problem
from ..contracts.ids import new_request_id

log = logging.getLogger("agentshield")
PROBLEM = "application/problem+json"
_CODE_BY_STATUS = {404: "not_found", 405: "not_found", 401: "unauthenticated", 403: "forbidden",
                   413: "payload_too_large"}


# Proxy routes answer in the provider's own error shape so agent SDKs handle failures natively.
PROXY_API_BY_PATH = {"/v1/messages": "anthropic", "/v1/chat/completions": "openai", "/v1/models": "openai"}
_PROVIDER_TYPES: dict[str, tuple[str, str, str]] = {   # code -> (anthropic type, openai type, openai code)
    "unauthenticated": ("authentication_error", "invalid_request_error", "invalid_api_key"),
    "forbidden": ("permission_error", "invalid_request_error", "forbidden"),
    "credential_mismatch": ("permission_error", "invalid_request_error", "forbidden"),
    "not_found": ("not_found_error", "invalid_request_error", "not_found"),
    "rate_limited": ("rate_limit_error", "rate_limit_error", "rate_limit_exceeded"),
    "budget_exceeded": ("rate_limit_error", "rate_limit_error", "budget_exceeded"),
    "payload_too_large": ("request_too_large", "invalid_request_error", "request_too_large"),
    "validation_failed": ("invalid_request_error", "invalid_request_error", "invalid_request"),
    "upstream_error": ("api_error", "server_error", "upstream_error"),
    "upstream_timeout": ("timeout_error", "server_error", "upstream_timeout"),
    "internal": ("api_error", "server_error", "internal_error"),
}


def provider_error_response(request: Request, api: str, code: str, message: str, *, status: int,
                            headers: dict[str, str] | None = None) -> JSONResponse:
    a_type, o_type, o_code = _PROVIDER_TYPES.get(code, ("invalid_request_error", "invalid_request_error", code))
    rid = getattr(request.state, "request_id", None)
    if api == "anthropic":
        body: dict[str, Any] = {"type": "error", "error": {"type": a_type, "message": message}, "request_id": rid}
    else:
        body = {"error": {"message": message, "type": o_type, "param": None, "code": o_code}}
    return JSONResponse(body, status_code=status, headers=headers)


def problem_response(request: Request, code: str, detail: str | None = None, *, status: int | None = None,
                     errors: list[dict[str, object]] | None = None,
                     headers: dict[str, str] | None = None, title: str | None = None) -> JSONResponse:
    p = Problem(code=code, title=title or code.replace("_", " ").capitalize(),
                status=status or STATUS_BY_CODE[code], detail=detail, instance=request.url.path,
                request_id=getattr(request.state, "request_id", None), errors=errors)
    return JSONResponse(p.model_dump(mode="json", exclude_none=True), status_code=p.status,
                        media_type=PROBLEM, headers=headers)


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        rid = request.headers.get("x-request-id") or new_request_id()
        request.state.request_id = rid[:80]
        response = await call_next(request)
        response.headers["X-Request-Id"] = request.state.request_id
        return response


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        proxy_api = PROXY_API_BY_PATH.get(request.url.path)
        if proxy_api:
            return provider_error_response(request, proxy_api, exc.code, exc.detail or exc.title,
                                           status=exc.status, headers=exc.headers)
        return problem_response(request, exc.code, exc.detail, errors=exc.errors,
                                headers=exc.headers, title=exc.title)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        errs = [{"path": ".".join(str(x) for x in e["loc"]), "message": e["msg"]} for e in exc.errors()]
        return problem_response(request, "validation_failed", "Request validation failed", errors=errs)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _CODE_BY_STATUS.get(exc.status_code, "internal" if exc.status_code >= 500 else "validation_failed")
        return problem_response(request, code, str(exc.detail), status=exc.status_code)

    @app.exception_handler(DBAPIError)
    async def _database(request: Request, exc: DBAPIError) -> JSONResponse:
        # Text that Postgres cannot store (a NUL character) is the caller's mistake, not an outage.
        msg = str(exc.orig).lower() if exc.orig is not None else ""
        if any(m in msg for m in ("\\u0000", "null byte", "invalid byte sequence", "unsupported unicode escape", "nul (0x00)")):
            return problem_response(request, "validation_failed", "Text contains characters that cannot be stored (such as a NUL byte)")
        log.exception("database error request_id=%s", getattr(request.state, "request_id", ""))
        return problem_response(request, "internal", "Internal error")

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error request_id=%s", getattr(request.state, "request_id", ""))
        return problem_response(request, "internal", "Internal error")
