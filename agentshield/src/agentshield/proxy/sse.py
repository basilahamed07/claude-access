"""Incremental Server-Sent-Events parsing. Chunk boundaries are arbitrary (even 1 byte)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

_BOUNDARY = re.compile(rb"\r?\n\r?\n")
MAX_EVENT_BYTES = 8 * 1024 * 1024


class SseError(Exception):
    pass


@dataclass
class SseEvent:
    event: str | None
    data: str
    raw: bytes            # the exact bytes of the event including its terminating blank line

    def json(self) -> Any | None:
        try:
            return json.loads(self.data)
        except ValueError:
            return None


def parse_block(raw: bytes) -> SseEvent:
    event: str | None = None
    data_lines: list[str] = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if not line or line.startswith(":"):
            continue
        name, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if name == "event":
            event = value
        elif name == "data":
            data_lines.append(value)
    return SseEvent(event=event, data="\n".join(data_lines), raw=raw)


class SseParser:
    def __init__(self) -> None:
        self._buf = b""

    def feed(self, chunk: bytes) -> list[SseEvent]:
        self._buf += chunk
        out: list[SseEvent] = []
        while (m := _BOUNDARY.search(self._buf)) is not None:
            raw, self._buf = self._buf[:m.end()], self._buf[m.end():]
            out.append(parse_block(raw))
        if len(self._buf) > MAX_EVENT_BYTES:
            raise SseError("SSE event too large")
        return out

    def remainder(self) -> bytes:
        rest, self._buf = self._buf, b""
        return rest


def format_event(name: str | None, payload: Any) -> bytes:
    data = payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"))
    head = f"event: {name}\n" if name else ""
    return f"{head}data: {data}\n\n".encode()
