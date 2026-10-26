"""Parse + validate + compile a policy YAML document, with line numbers on every error."""

from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass, field
from typing import Any

import yaml
from pydantic import ValidationError

from ..contracts.decision import EffectTag
from ..contracts.policy import PolicyDoc, RuleDoc
from .conditions import ConditionError, compile_condition

MAX_POLICY_BYTES = 256 * 1024
GLOB_CHARS = set("*?[")


@dataclass
class LineError:
    line: int
    path: str
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {"line": self.line, "path": self.path, "message": self.message}


class PolicyError(Exception):
    def __init__(self, errors: list[LineError]) -> None:
        super().__init__("; ".join(f"line {e.line}: {e.message}" for e in errors))
        self.errors = errors


class _UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark)
            seen.add(key)
        return super().construct_mapping(node, deep)


@dataclass
class CompiledRule:
    doc: RuleDoc
    condition: Any
    is_glob: bool


@dataclass
class CompiledPolicy:
    doc: PolicyDoc
    rules: list[CompiledRule]
    sha256: bytes
    tool_tag_exact: dict[str, EffectTag] = field(default_factory=dict)
    tool_tag_globs: list[tuple[str, EffectTag]] = field(default_factory=list)

    def tag_for(self, tool: str, advised: EffectTag | None = None) -> EffectTag:
        if tool in self.tool_tag_exact:
            return self.tool_tag_exact[tool]
        for pattern, tag in self.tool_tag_globs:
            if fnmatch.fnmatchcase(tool, pattern):
                return tag
        for r in self.rules:
            if r.doc.effect_tag and tool_matches(r, tool):
                return r.doc.effect_tag
        return advised or EffectTag.external


def tool_matches(rule: CompiledRule, tool: str) -> bool:
    return fnmatch.fnmatchcase(tool, rule.doc.tool) if rule.is_glob else tool == rule.doc.tool


# ── line numbers ───────────────────────────────────────────────────────────────────────────────
def _line_for(root: yaml.Node | None, path: tuple[Any, ...]) -> int:
    node, best = root, 1
    if node is None:
        return best
    best = node.start_mark.line + 1
    for part in path:
        if isinstance(node, yaml.MappingNode):
            nxt = None
            for k, v in node.value:
                if getattr(k, "value", None) == part:
                    best, nxt = k.start_mark.line + 1, v
                    break
            if nxt is None:
                return best
            node = nxt
        elif isinstance(node, yaml.SequenceNode) and isinstance(part, int) and part < len(node.value):
            node = node.value[part]
            best = node.start_mark.line + 1
        else:
            return best
    return best


def _fmt(path: tuple[Any, ...]) -> str:
    out = ""
    for p in path:
        out += f"[{p}]" if isinstance(p, int) else (f".{p}" if out else str(p))
    return out or "(document)"


def _clean(msg: str) -> str:
    return msg.removeprefix("Value error, ")


def parse_policy(text: str) -> CompiledPolicy:
    if len(text.encode()) > MAX_POLICY_BYTES:
        raise PolicyError([LineError(1, "(document)", f"policy is larger than {MAX_POLICY_BYTES // 1024} KB")])
    try:
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.AliasEvent):
                raise PolicyError([LineError((event.start_mark.line if event.start_mark else 0) + 1, "(document)",
                                             "YAML aliases and anchors are not allowed in policies")])
        root = yaml.compose(text, Loader=yaml.SafeLoader)
        data = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506  (SafeLoader subclass)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
        line = (mark.line + 1) if mark else 1
        problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        raise PolicyError([LineError(line, "(document)", f"invalid YAML: {problem}")]) from exc
    if not isinstance(data, dict):
        raise PolicyError([LineError(1, "(document)", "a policy must be a YAML mapping with 'version' and 'rules'")])
    try:
        doc = PolicyDoc.model_validate(data)
    except ValidationError as exc:
        raise PolicyError([
            LineError(_line_for(root, tuple(e["loc"])), _fmt(tuple(e["loc"])), _clean(e["msg"]))
            for e in exc.errors()]) from exc

    errors: list[LineError] = []

    def err(path: tuple[Any, ...], message: str) -> None:
        errors.append(LineError(_line_for(root, path), _fmt(path), message))

    seen: set[str] = set()
    compiled: list[CompiledRule] = []
    for i, rule in enumerate(doc.rules):
        if rule.id in seen:
            err(("rules", i, "id"), f"duplicate rule id '{rule.id}'")
        seen.add(rule.id)
        try:
            cond = compile_condition(rule.when, doc.scopes, ("rules", i, "when"))
        except ConditionError as ce:
            err(ce.path, ce.message)
            continue
        compiled.append(CompiledRule(rule, cond, bool(GLOB_CHARS & set(rule.tool))))
    for name, values in doc.scopes.items():
        if not values or not all(isinstance(v, str) and v for v in values):
            err(("scopes", name), "a scope must be a non-empty list of strings")
    if errors:
        raise PolicyError(sorted(errors, key=lambda e: e.line))
    policy = CompiledPolicy(doc, compiled, hashlib.sha256(text.encode()).digest())
    for pattern, spec in doc.tools.items():
        if GLOB_CHARS & set(pattern):
            policy.tool_tag_globs.append((pattern, spec.effect_tag))
        else:
            policy.tool_tag_exact[pattern] = spec.effect_tag
    return policy
