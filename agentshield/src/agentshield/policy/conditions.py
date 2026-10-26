"""Policy conditions: compile-time validation and run-time evaluation.

A condition is one of:
  {arg: <dotted path>, op: <operator>, value: <v>}      test a tool argument
  {session: risk_score, op: <numeric op>, value: <n>}   test the session state
  {all: [...]} | {any: [...]} | {not: <cond>}           combinators (a bare list means all)

Operators: eq ne in not_in regex glob domain_in not_domain_in gt gte lt lte in_scope not_in_scope exists.
Comparisons that cannot be evaluated (missing argument, wrong type) are False, EXCEPT `not_*`
operators, which are True when the value is not provably inside the allowed set: an unparsable
recipient must never slip past a "recipient not in approved domains" block rule.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any

import regex

OPERATORS = {"eq", "ne", "in", "not_in", "regex", "glob", "domain_in", "not_domain_in", "gt", "gte", "lt", "lte",
             "in_scope", "not_in_scope", "exists"}
NUMERIC_OPS = {"gt", "gte", "lt", "lte"}
SESSION_FIELDS = {"risk_score"}
REGEX_TIMEOUT = 0.05
MAX_REGEX_LEN = 500
MAX_TEXT = 8192
_EMAIL = re.compile(r"[A-Za-z0-9._%+'-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
_URL_HOST = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^/@]*@)?([^/:?#]+)")
_BARE_DOMAIN = re.compile(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


class ConditionError(ValueError):
    def __init__(self, path: tuple[str | int, ...], message: str) -> None:
        super().__init__(message)
        self.path = path
        self.message = message


class EvaluationError(Exception):
    """Raised for conditions that cannot be evaluated safely (e.g. regex timeout); callers fail closed."""


@dataclass
class Env:
    args: dict[str, Any]
    risk_score: float
    scopes: dict[str, list[str]]


def lookup(args: Any, path: str) -> tuple[bool, Any]:
    cur = args
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return False, None
    return True, cur


def _as_list(v: Any) -> list[Any]:
    return list(v) if isinstance(v, (list, tuple)) else [v]


def extract_domains(value: Any) -> list[str | None]:
    """One entry per recipient/URL found in `value`; None where nothing parsable was found."""
    out: list[str | None] = []
    for item in _as_list(value):
        if not isinstance(item, str):
            out.append(None)
            continue
        found = [m.group(1).lower() for m in _EMAIL.finditer(item)]
        if not found:
            url = _URL_HOST.match(item.strip())
            if url:
                found = [url.group(1).lower()]
            elif _BARE_DOMAIN.match(item.strip()):
                found = [item.strip().lower()]
        out.extend(found or [None])
    return out


def domain_matches(domain: str, pattern: str) -> bool:
    pattern = pattern.lower().strip()
    if pattern.startswith("*."):
        return domain.endswith(pattern[1:]) and domain != pattern[2:]
    return domain == pattern


def _num(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip())
        except ValueError:
            return None
    return None


@dataclass
class Leaf:
    source: str                  # "arg" or "session"
    path: str
    op: str
    value: Any
    pattern: Any = None          # compiled regex
    scope_name: str | None = None

    def test(self, env: Env) -> bool:
        if self.source == "session":
            return _compare_numeric(self.op, env.risk_score, self.value)
        present, arg = lookup(env.args, self.path)
        op = self.op
        if op == "exists":
            return (present and arg is not None) == bool(self.value)
        if not present or arg is None:
            return op in {"not_in", "not_domain_in", "not_in_scope", "ne"}
        if op in {"in_scope", "not_in_scope"}:
            allowed = env.scopes.get(self.scope_name or "", [])
            return _in(arg, allowed) if op == "in_scope" else not _in(arg, allowed)
        if op == "in":
            return _in(arg, self.value)
        if op == "not_in":
            return not any(_eq(a, v) for a in _as_list(arg) for v in self.value)
        if op == "eq":
            return _eq(arg, self.value)
        if op == "ne":
            return not _eq(arg, self.value)
        if op in NUMERIC_OPS:
            return _compare_numeric(op, arg, self.value)
        if op == "glob":
            return any(isinstance(a, str) and fnmatch.fnmatchcase(a, self.value) for a in _as_list(arg))
        if op == "regex":
            return self._regex(arg)
        if op in {"domain_in", "not_domain_in"}:
            domains = extract_domains(arg)
            inside = [d is not None and any(domain_matches(d, p) for p in self.value) for d in domains]
            return all(inside) if op == "domain_in" else not all(inside)
        return False

    def _regex(self, arg: Any) -> bool:
        for a in _as_list(arg):
            if not isinstance(a, str):
                continue
            try:
                if self.pattern.search(a[:MAX_TEXT], timeout=REGEX_TIMEOUT):
                    return True
            except TimeoutError as exc:
                raise EvaluationError("regex evaluation timed out") from exc
        return False


def _eq(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    na, nb = _num(a) if not isinstance(a, str) else None, _num(b) if not isinstance(b, str) else None
    if na is not None and nb is not None:
        return na == nb
    return bool(a == b)


def _in(arg: Any, allowed: list[Any]) -> bool:
    items = _as_list(arg)
    return bool(items) and all(any(_eq(i, v) for v in allowed) for i in items)


def _compare_numeric(op: str, left: Any, right: Any) -> bool:
    a, b = _num(left), _num(right)
    if a is None or b is None:
        return False
    return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]


@dataclass
class All:
    items: list[Any]

    def test(self, env: Env) -> bool:
        return all(i.test(env) for i in self.items)


@dataclass
class Any_:
    items: list[Any]

    def test(self, env: Env) -> bool:
        return any(i.test(env) for i in self.items)


@dataclass
class Not:
    item: Any

    def test(self, env: Env) -> bool:
        return not self.item.test(env)


class Always:
    def test(self, env: Env) -> bool:
        return True


def compile_condition(node: Any, scopes: dict[str, list[str]], path: tuple[str | int, ...] = ()) -> Any:
    if node is None:
        return Always()
    if isinstance(node, list):
        return All([compile_condition(n, scopes, (*path, i)) for i, n in enumerate(node)])
    if not isinstance(node, dict):
        raise ConditionError(path, "a condition must be a mapping or a list of conditions")
    keys = set(node)
    if keys & {"all", "any", "not"}:
        if len(keys) != 1:
            raise ConditionError(path, "all/any/not cannot be mixed with other keys")
        (k,) = keys
        if k == "not":
            return Not(compile_condition(node["not"], scopes, (*path, "not")))
        items = node[k]
        if not isinstance(items, list) or not items:
            raise ConditionError((*path, k), f"'{k}' needs a non-empty list")
        built = [compile_condition(n, scopes, (*path, k, i)) for i, n in enumerate(items)]
        return All(built) if k == "all" else Any_(built)
    unknown = keys - {"arg", "session", "op", "value"}
    if unknown:
        raise ConditionError(path, f"unknown key(s): {', '.join(sorted(map(str, unknown)))}")
    if ("arg" in node) == ("session" in node):
        raise ConditionError(path, "use exactly one of 'arg' or 'session'")
    op = node.get("op")
    if op not in OPERATORS:
        raise ConditionError((*path, "op"), f"unknown operator {op!r}; use one of: {', '.join(sorted(OPERATORS))}")
    value = node.get("value")
    if "session" in node:
        if node["session"] not in SESSION_FIELDS:
            raise ConditionError((*path, "session"), f"unknown session field; use: {', '.join(sorted(SESSION_FIELDS))}")
        if op not in NUMERIC_OPS or _num(value) is None:
            raise ConditionError((*path, "op"), "session conditions need a numeric operator (gt, gte, lt, lte) and a number")
        return Leaf("session", str(node["session"]), op, value)
    arg = node["arg"]
    if not isinstance(arg, str) or not arg:
        raise ConditionError((*path, "arg"), "'arg' must be a dotted argument path such as 'to' or 'payload.to'")
    leaf = Leaf("arg", arg, op, value)
    _validate_value(leaf, scopes, path)
    return leaf


def _validate_value(leaf: Leaf, scopes: dict[str, list[str]], path: tuple[str | int, ...]) -> None:
    op, v = leaf.op, leaf.value
    vp = (*path, "value")
    if op in {"in", "not_in", "domain_in", "not_domain_in"}:
        if not isinstance(v, list) or not v:
            raise ConditionError(vp, f"'{op}' needs a non-empty list")
        if op.endswith("domain_in") and not all(isinstance(x, str) and x.strip() for x in v):
            raise ConditionError(vp, "domains must be non-empty strings such as 'acme.com' or '*.acme.com'")
    elif op in NUMERIC_OPS:
        if _num(v) is None:
            raise ConditionError(vp, f"'{op}' needs a number")
    elif op in {"in_scope", "not_in_scope"}:
        if not isinstance(v, str) or v not in scopes:
            raise ConditionError(vp, f"unknown scope {v!r}; define it under 'scopes:'")
        leaf.scope_name = v
    elif op == "regex":
        if not isinstance(v, str) or not v or len(v) > MAX_REGEX_LEN:
            raise ConditionError(vp, f"'regex' needs a pattern of 1-{MAX_REGEX_LEN} characters")
        try:
            leaf.pattern = regex.compile(v)
        except regex.error as exc:
            raise ConditionError(vp, f"invalid regular expression: {exc}") from exc
    elif op == "glob":
        if not isinstance(v, str) or not v:
            raise ConditionError(vp, "'glob' needs a pattern string")
    elif op == "exists":
        if not isinstance(v, bool):
            raise ConditionError(vp, "'exists' needs true or false")
    elif op in {"eq", "ne"} and isinstance(v, (list, dict)):
        raise ConditionError(vp, f"'{op}' compares a single value; use 'in' for lists")
