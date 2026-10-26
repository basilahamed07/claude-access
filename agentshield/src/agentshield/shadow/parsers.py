"""Log parsers. One bad line never fails a batch: it is counted as rejected."""

from __future__ import annotations

import csv
import io
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

MAX_LINE = 4000
FORMATS = ("squid", "common", "dns", "csv", "records")


@dataclass
class Hit:
    ts: datetime
    user: str | None
    team: str | None
    host: str
    path: str
    bytes_out: int


class LineError(ValueError):
    pass


def _host_path(target: str) -> tuple[str, str]:
    t = target.strip()
    if "://" in t:
        u = urlsplit(t)
        return (u.hostname or ""), (u.path or "") + (f"?{u.query}" if u.query else "")
    if re.fullmatch(r"[\w.-]+:\d+", t):                       # CONNECT host:443
        return t.rsplit(":", 1)[0], ""
    if "/" in t:
        h, _, p = t.partition("/")
        return h.split(":")[0], "/" + p
    return t.split(":")[0], ""


def _ts(value: str) -> datetime:
    v = value.strip()
    try:
        return datetime.fromtimestamp(float(v), UTC)
    except ValueError:
        pass
    for fmt in ("%d/%b/%Y:%H:%M:%S %z",):
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            continue
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=UTC)
    except ValueError as exc:
        raise LineError("unreadable timestamp") from exc


def _int(v: Any) -> int:
    try:
        return max(0, int(float(v)))
    except (TypeError, ValueError):
        return 0


def parse_squid(line: str) -> Hit:
    f = line.split()
    if len(f) < 7:
        raise LineError("too few fields")
    user = f[7] if len(f) > 7 and f[7] != "-" else f[2]          # logged-in user if there is one, else the client address
    host, path = _host_path(f[6])
    if not host:
        raise LineError("no host")
    return Hit(_ts(f[0]), user, None, host, path, 0)


_COMMON = re.compile(r'^(?P<client>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<target>\S+)[^"]*" (?P<status>\d{3}) (?P<bytes>\d+|-)')


def parse_common(line: str) -> Hit:
    m = _COMMON.match(line)
    if not m:
        raise LineError("not a common log line")
    host, path = _host_path(m["target"])
    if not host:
        raise LineError("no host")
    user = m["user"] if m["user"] != "-" else m["client"]
    return Hit(_ts(m["ts"]), user, None, host, path, 0)


def parse_dns(line: str) -> Hit:
    f = line.replace(",", " ").split()
    if len(f) < 3:
        raise LineError("too few fields")
    return Hit(_ts(f[0]), f[1], None, f[2].rstrip("."), "", 0)


_SYN = {"ts": ("ts", "time", "timestamp", "date", "datetime"), "user": ("user", "username", "user_id", "client", "src", "source_ip"),
        "team": ("team", "department", "group", "ou"), "host": ("host", "hostname", "domain", "dest_host", "destination"),
        "url": ("url", "uri", "request_url"), "bytes_out": ("bytes_out", "bytes_sent", "upload_bytes", "sent", "request_bytes")}


def _pick(row: dict[str, Any], key: str) -> Any:
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for name in _SYN[key]:
        if name in lowered and lowered[name] not in (None, ""):
            return lowered[name]
    return None


def parse_record(row: dict[str, Any]) -> Hit:
    ts, host, url = _pick(row, "ts"), _pick(row, "host"), _pick(row, "url")
    if ts is None or (host is None and url is None):
        raise LineError("needs a timestamp and a host or url")
    h, p = _host_path(str(url)) if url else (str(host), "")
    if host and not url:
        h, p = _host_path(str(host))
    if not h:
        raise LineError("no host")
    user, team = _pick(row, "user"), _pick(row, "team")
    return Hit(_ts(str(ts)), str(user) if user is not None else None, str(team)[:100] if team is not None else None, h, p, _int(_pick(row, "bytes_out")))


def parse(fmt: str, lines: Iterable[str] | None, records: Iterable[dict[str, Any]] | None) -> tuple[list[Hit], int, list[str]]:
    """(hits, rejected_count, up to 5 sample reasons)."""
    hits: list[Hit] = []
    rejected = 0
    samples: list[str] = []

    def reject(reason: str) -> None:
        nonlocal rejected
        rejected += 1
        if len(samples) < 5:
            samples.append(reason)

    if fmt == "records":
        for row in records or []:
            try:
                hits.append(parse_record(row))
            except (LineError, TypeError, AttributeError) as exc:
                reject(str(exc))
        return hits, rejected, samples
    raw = [ln for ln in (lines or []) if ln.strip()]
    if fmt == "csv":
        rows = list(csv.DictReader(io.StringIO("\n".join(raw))))
        for row in rows:
            try:
                hits.append(parse_record(row))
            except (LineError, TypeError) as exc:
                reject(str(exc))
        return hits, rejected, samples
    parser = {"squid": parse_squid, "common": parse_common, "dns": parse_dns}[fmt]
    for ln in raw:
        if ln.startswith("#"):
            continue
        if len(ln) > MAX_LINE:
            reject("line too long")
            continue
        try:
            hits.append(parser(ln))
        except LineError as exc:
            reject(str(exc))
    return hits, rejected, samples
