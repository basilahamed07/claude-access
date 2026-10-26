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
    ok = all(v == "ok" for v in checks.values())
    return JSONResponse({"status": "ok" if ok else "unavailable", **checks}, status_code=200 if ok else 503)
