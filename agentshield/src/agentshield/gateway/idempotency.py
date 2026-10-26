"""`Idempotency-Key` support for POSTs on the control plane (api spec §A.1.7).

Scoped by the caller's credential (hash), method, path and key, so one tenant can never replay or
collide with another's. Only 2xx responses are stored (24 h). Same key + same body replays the first
response; same key + different body is 409 `idempotency_conflict`.
"""

from __future__ import annotations

import base64
import hashlib
import json

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from .errors import problem_response
from .state import get_state

TTL = 24 * 3600
_PREFIXES = ("/v1/admin/", "/v1/signup")


def _cred_hash(request: Request) -> str:
    cred = "|".join([request.headers.get("authorization", ""), request.headers.get("x-api-key", ""),
                     request.cookies.get("as_session", ""), request.client.host if request.client else ""])
    return hashlib.sha256(cred.encode()).hexdigest()[:24]


class IdempotencyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        key = request.headers.get("idempotency-key")
        if request.method != "POST" or not key or not request.url.path.startswith(_PREFIXES):
            return await call_next(request)
        if len(key) > 200:
            return problem_response(request, "validation_failed", "Idempotency-Key too long")
        redis = get_state(request).redis
        rkey = f"idem:{_cred_hash(request)}:{request.url.path}:{hashlib.sha256(key.encode()).hexdigest()}"
        body = await request.body()
        body_sha = hashlib.sha256(body).hexdigest()
        existing = await redis.get(rkey)
        if existing:
            rec = json.loads(existing)
            if rec["state"] == "pending":
                return problem_response(request, "conflict", "A request with this Idempotency-Key is in progress")
            if rec["body_sha"] != body_sha:
                return problem_response(request, "idempotency_conflict",
                                        "Idempotency-Key was already used with a different request body")
            return Response(base64.b64decode(rec["body"]), status_code=rec["status"],
                            media_type=rec["content_type"], headers={"Idempotency-Replayed": "true"})
        claimed = await redis.set(rkey, json.dumps({"state": "pending", "body_sha": body_sha}), ex=120, nx=True)
        if not claimed:
            return problem_response(request, "conflict", "A request with this Idempotency-Key is in progress")
        response = await call_next(request)
        chunks = [chunk async for chunk in response.body_iterator]  # type: ignore[attr-defined]
        payload = b"".join(c if isinstance(c, bytes) else c.encode() for c in chunks)
        if 200 <= response.status_code < 300:
            await redis.set(rkey, json.dumps({
                "state": "done", "body_sha": body_sha, "status": response.status_code,
                "content_type": response.headers.get("content-type", "application/json"),
                "body": base64.b64encode(payload).decode()}), ex=TTL)
        else:
            await redis.delete(rkey)
        headers = {k: v for k, v in response.headers.items() if k.lower() not in {"content-length"}}
        return Response(payload, status_code=response.status_code, headers=headers)
