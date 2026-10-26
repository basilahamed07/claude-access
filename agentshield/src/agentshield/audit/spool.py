"""Bounded local spool used when Redis is unreachable, so events are not lost (and requests never block)."""

from __future__ import annotations

import json
import os
from collections import deque
from pathlib import Path
from typing import Any

MAX_SPOOL = 10_000


class Spool:
    def __init__(self, directory: str | Path, *, max_items: int = MAX_SPOOL) -> None:
        self.dir = Path(directory)
        self.max_items = max_items
        self.items: deque[dict[str, Any]] = deque()
        self.dropped = 0
        self.first_ts: str | None = None
        self.last_ts: str | None = None
        self._loaded = False

    @property
    def path(self) -> Path:
        return self.dir / "spool.jsonl"

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            for line in self.path.read_text().splitlines():
                if line.strip():
                    self.items.append(json.loads(line))
        except (OSError, ValueError):
            pass

    def __len__(self) -> int:
        self._load()
        return len(self.items)

    def add(self, record: dict[str, Any]) -> None:
        self._load()
        if len(self.items) >= self.max_items:
            self.items.popleft()
            self.dropped += 1
        self.items.append(record)
        ts = str(json.loads(record["event"]).get("ts", ""))
        self.first_ts = self.first_ts or ts
        self.last_ts = ts
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write(json.dumps(record) + "\n")
        except OSError:
            pass            # memory copy still holds it

    def drain(self) -> list[dict[str, Any]]:
        self._load()
        return list(self.items)

    def clear(self) -> tuple[int, int, str | None, str | None]:
        n, d, a, b = len(self.items), self.dropped, self.first_ts, self.last_ts
        self.items.clear()
        self.dropped, self.first_ts, self.last_ts = 0, None, None
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass
        return n, d, a, b
