"""Write the OpenAPI contract to agentshield/openapi.json (or check it: `--check` exits 1 if it is stale).

The dashboard (F1) and the SDK (E2) are generated from this file, so a route change that is not
reflected here fails `tests/contract/test_openapi_snapshot.py`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agentshield.gateway.app import create_app
from agentshield.settings import Settings

TARGET = Path(__file__).resolve().parents[1] / "openapi.json"


def build() -> str:
    app = create_app(Settings(env="dev"))
    return json.dumps(app.openapi(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    fresh = build()
    if "--check" in argv:
        if not TARGET.exists() or TARGET.read_text() != fresh:
            print("openapi.json is out of date: run `python scripts/export_openapi.py`", file=sys.stderr)
            return 1
        return 0
    TARGET.write_text(fresh)
    print(f"wrote {TARGET} ({len(fresh)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
