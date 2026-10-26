"""RFC 9457 problem+json rendering for every non-proxy route (api spec §A.5)."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from ..contracts.errors import STATUS_BY_CODE, ApiError, Problem
from ..contracts.ids import new_request_id

log = logging.getLogger("agentshield")
PROBLEM = "application/problem+json"
_CODE_BY_STATUS = {404: "not_found", 405: "not_found", 401: "unauthenticated", 403: "forbidden",
                   413: "payload_too_large"}


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

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error request_id=%s", getattr(request.state, "request_id", ""))
        return problem_response(request, "internal", "Internal error")
