"""Id helpers: time-sortable trace/event ids and the agent slug format (arch §3)."""

from __future__ import annotations

import re

from ulid import ULID

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")


def new_trace_id() -> str:
    return f"t-{ULID()}"


def new_event_id() -> str:
    return f"evt_{ULID()}"


def new_request_id() -> str:
    return f"req_{ULID()}"
