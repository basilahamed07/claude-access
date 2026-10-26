from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from ..state import get_state

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request) -> JSONResponse:
    state = get_state(request)
    checks: dict[str, str] = {}
    try:
        async with state.engine.connect() as conn:
            await conn.execute(text("select 1"))
        checks["database"] = "ok"
    except Exception:  # noqa: BLE001
        checks["database"] = "down"
    try:
        await state.redis.ping()
        checks["redis"] = "ok"
    except Exception:  # noqa: BLE001
        checks["redis"] = "down"
    clf = state.classifier
    checks["classifier"] = clf.status                       # ok | disabled | degraded: never silently "clean"
    if clf.status == "degraded":
        checks["classifier_reason"] = clf.reason[:200]
    ok = all(v == "ok" for k, v in checks.items() if k in {"database", "redis"})
    return JSONResponse({"status": "ok" if ok else "unavailable", **checks}, status_code=200 if ok else 503)
