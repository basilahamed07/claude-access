"""Small HTTP helpers shared by control-plane routes."""

from __future__ import annotations

from fastapi import Request

from ..contracts.errors import ApiError


def require_if_match(request: Request, current_etag: str) -> None:
    """Optimistic concurrency: 428 when the header is missing, 412 when stale (api spec §A.1.8)."""
    sent = request.headers.get("if-match")
    if not sent:
        raise ApiError("precondition_required", "This change requires an If-Match header with the resource ETag")
    if sent.strip() not in {current_etag, current_etag.removeprefix("W/")} and sent.strip() != "*":
        raise ApiError("precondition_failed", "The resource changed since you loaded it; reload and retry")
