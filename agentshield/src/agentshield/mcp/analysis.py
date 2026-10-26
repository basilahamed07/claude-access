"""Pure MCP server analysis: fingerprint, tool-description scan, capability review, source heuristics, verdict.

Everything here is deterministic and offline; reaching a server and storing the result live elsewhere. The report always lists
the checks that ran AND the ones that did not (`sandbox` never runs here), so a clean report is never read as "fully audited".
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from ..scan.pipeline import ScanConfig, scan

Severity = Literal["info", "low", "medium", "high"]
CAPABILITIES = ("exec", "filesystem", "network", "database", "external", "credentials")
SEP = "__"                                       # namespaced tool name: <server>__<tool>
MAX_TOOLS = 200
MAX_TEXT = 20_000


@dataclass
class Tool:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mcp(cls, raw: dict[str, Any]) -> Tool:
        schema = raw.get("inputSchema") or raw.get("input_schema") or {}
        return cls(str(raw.get("name", ""))[:200], str(raw.get("description") or "")[:MAX_TEXT], schema if isinstance(schema, dict) else {})

    def to_mcp(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "inputSchema": self.input_schema}


@dataclass
class Finding:
    check: str
    severity: Severity
    message: str
    tool: str | None = None
    rule_id: str | None = None
    excerpt: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"check": self.check, "severity": self.severity, "message": self.message, "tool": self.tool, "rule_id": self.rule_id, "excerpt": self.excerpt[:200]}


def _canonical(tools: list[Tool]) -> bytes:
    body: list[dict[str, Any]] = sorted(({"name": t.name, "description": t.description, "inputSchema": t.input_schema} for t in tools), key=lambda d: str(d["name"]))
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def fingerprint(tools: list[Tool]) -> bytes:
    """sha256 over the canonical JSON of every tool's name, description and schema. Order of tools and keys does not matter."""
    return hashlib.sha256(_canonical(tools)).digest()


def namespaced(server: str, tool: str) -> str:
    return f"{server}{SEP}{tool}"


def split_namespaced(name: str) -> tuple[str, str] | None:
    server, sep, tool = name.partition(SEP)
    return (server, tool) if sep and server and tool else None


# ── tool descriptions (reuses the M2 scanner) ──────────────────────────────────────────────────────────
def _texts(tool: Tool) -> list[tuple[str, str]]:
    """Every string a model will read about a tool: name, description and each schema property's description/enum/default."""
    out = [("name", tool.name), ("description", tool.description)]

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k in {"description", "title"} and isinstance(v, str):
                    out.append((f"schema {path}{k}", v))
                elif k in {"default", "examples", "enum", "const"}:
                    for s in ([v] if not isinstance(v, list) else v):
                        if isinstance(s, str):
                            out.append((f"schema {path}{k}", s))
                else:
                    walk(v, f"{path}{k}.")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}{i}.")

    walk(tool.input_schema, "")
    return [(w, t) for w, t in out if t.strip()]


async def scan_descriptions(tools: list[Tool], cfg: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        for where, text in _texts(tool):
            res = await scan(text, source="mcp_tool_description", cfg=cfg)
            if res.verdict == "clean" and "hidden_content" not in res.flags and "obfuscated" not in res.flags:
                continue
            sev: Severity = "high" if res.verdict == "malicious" else "medium"
            rules = ", ".join(sorted({f.rule_id for f in res.findings})[:4]) or "classifier"
            findings.append(Finding("tool_description", sev, f"{tool.name}: the {where} {'contains instructions aimed at the model' if res.verdict == 'malicious' else 'looks suspicious'} ({rules})",
                                    tool.name, res.findings[0].rule_id if res.findings else None, text[:200]))
            if "hidden_content" in res.flags or "obfuscated" in res.flags:
                findings.append(Finding("tool_description", "medium", f"{tool.name}: the {where} contains hidden or obfuscated text", tool.name, None, text[:200]))
    return findings


def check_names(tools: list[Tool], other_servers: dict[str, list[str]], reserved: set[str] | None = None) -> list[Finding]:
    """Duplicate names within the server, names that collide with another approved server's tools (shadowing), and names that break the namespacing."""
    findings: list[Finding] = []
    seen: set[str] = set()
    taken = {n: s for s, names in other_servers.items() for n in names}
    for t in tools:
        low = t.name.lower()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", t.name):
            findings.append(Finding("tool_names", "medium", f"{t.name[:40]!r} is not a plain tool name", t.name))
        if SEP in t.name:
            findings.append(Finding("tool_names", "medium", f"{t.name} contains '{SEP}', which AgentShield uses to namespace tools", t.name))
        if low in seen:
            findings.append(Finding("tool_names", "high", f"{t.name} is declared twice", t.name))
        seen.add(low)
        if t.name in taken:
            findings.append(Finding("tool_names", "high", f"{t.name} has the same name as a tool on approved server '{taken[t.name]}' (shadowing)", t.name))
        if reserved and t.name in reserved:
            findings.append(Finding("tool_names", "high", f"{t.name} is the name of one of the agent's own tools", t.name))
    return findings


# ── capabilities ─────────────────────────────────────────────────────────────────────────────────────
_PARAMS = {
    "exec": {"command", "cmd", "shell", "script", "code", "expression", "eval", "exec", "args_shell"},
    "filesystem": {"path", "file", "filepath", "filename", "directory", "dir", "paths"},
    "network": {"url", "uri", "endpoint", "host", "webhook", "hostname"},
    "database": {"sql", "statement", "dsn", "connection_string"},
    "credentials": {"password", "token", "api_key", "apikey", "secret", "credential", "credentials"},
}
_NAME_HINTS = {
    "exec": re.compile(r"(?:^|[_-])(?:exec|execute|run|shell|bash|eval|spawn)(?:$|[_-])", re.I),
    "external": re.compile(r"(?:^|[_-])(?:send|post|publish|notify|tweet|upload|transfer|pay|forward|reply)(?:$|[_-])", re.I),
    "filesystem": re.compile(r"(?:^|[_-])(?:read_file|write_file|delete_file|file|fs|directory)(?:$|[_-])", re.I),
    "network": re.compile(r"(?:^|[_-])(?:fetch|http|request|download|browse|crawl)(?:$|[_-])", re.I),
    "database": re.compile(r"(?:^|[_-])(?:sql|query_db|database)(?:$|[_-])", re.I),
}


def capabilities_of(tool: Tool) -> set[str]:
    caps: set[str] = set()
    props = (tool.input_schema.get("properties") or {}) if isinstance(tool.input_schema, dict) else {}
    for name in props:
        for cap, names in _PARAMS.items():
            if str(name).lower() in names:
                caps.add(cap)
    for cap, rx in _NAME_HINTS.items():
        if rx.search(tool.name):
            caps.add(cap)
    return caps


def review_capabilities(tools: list[Tool], declared: list[str]) -> tuple[list[Finding], dict[str, list[str]]]:
    by_tool = {t.name: sorted(capabilities_of(t)) for t in tools}
    findings: list[Finding] = []
    for t in tools:
        for cap in by_tool[t.name]:
            if cap in declared:
                continue
            sev: Severity = "high" if cap == "exec" else "medium"
            findings.append(Finding("capabilities", sev, f"{t.name} can use '{cap}', which this server did not declare", t.name))
    return findings, by_tool


# ── source heuristics ─────────────────────────────────────────────────────────────────────────────────
_SOURCE_RULES: list[tuple[str, Severity, str, re.Pattern[str]]] = [
    ("exec", "high", "runs shell commands or evaluates code", re.compile(r"\b(?:subprocess\.|os\.system|os\.popen|child_process|execSync|spawnSync|Runtime\.getRuntime\(\)\.exec)|shell\s*=\s*True|\beval\(|\bexec\(")),
    ("network", "medium", "makes outbound network calls", re.compile(r"\b(?:requests\.(?:get|post|put)|httpx\.|urllib\.request|aiohttp|axios\b|node-fetch|\bfetch\(|socket\.socket|net\.connect)")),
    ("filesystem", "medium", "writes or deletes files", re.compile(r"""open\([^)]*['"](?:w|a|wb|ab)['"]|fs\.(?:writeFile|appendFile|rm|unlink)|shutil\.rmtree|os\.(?:remove|unlink|rmdir)|\brm\s+-rf""")),
    ("secrets", "high", "contains what looks like a hard-coded secret", re.compile(r"AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|xox[abp]-[A-Za-z0-9-]{10,}")),
    ("obfuscation", "medium", "decodes and runs encoded payloads", re.compile(r"(?:b64decode|atob)\([^)]*\)[^\n]{0,40}(?:eval|exec)|(?:eval|exec)\([^\n]{0,40}(?:b64decode|atob)")),
]
_UNPINNED = re.compile(r"""(?mx) ^\s*(?:["']?[\w@/.-]+["']?\s*:\s*["'](?:\*|latest|next)["']  |  [\w.-]+\s*(?:==\s*)?$ )""")


def analyze_source(files: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for path, text in sorted(files.items()):
        body = text[: MAX_TEXT * 10]
        for check, sev, msg, rx in _SOURCE_RULES:
            m = rx.search(body)
            if m:
                line = body.count("\n", 0, m.start()) + 1
                shown = (m.group(0)[:4] + "…[masked]") if check == "secrets" else body[m.start(): m.end() + 40].replace("\n", " ")
                findings.append(Finding(f"source_{check}", sev, f"{path}:{line} {msg}", None, None, shown))
        if path.endswith(("requirements.txt", "package.json")) and _UNPINNED.search(body):
            findings.append(Finding("source_dependencies", "low", f"{path} has dependencies that are not pinned to a version"))
    return findings


# ── report and verdict ───────────────────────────────────────────────────────────────────────────────
CHECKS = [("tool_descriptions", "Tool descriptions scanned for instructions to the model"), ("tool_names", "Tool names checked for duplicates and shadowing"),
          ("capabilities", "Requested capabilities compared with the declared ones"), ("source", "Source files checked for risky code (heuristic)"),
          ("fingerprint", "Fingerprint of the tool list recorded"), ("sandbox", "Run in a locked-down sandbox with fake data")]


def recommend(findings: list[Finding], tools: list[Tool]) -> tuple[str, list[str] | None]:
    """(verdict, allowed_tools). A recommendation only: a person approves."""
    if any(f.severity == "high" for f in findings):
        return "rejected", None
    flagged = {f.tool for f in findings if f.tool and f.severity in {"medium", "high"}}
    if any(f.severity == "medium" and not f.tool for f in findings):
        return "approved_with_limits", [t.name for t in tools if t.name not in flagged]
    if flagged:
        return "approved_with_limits", [t.name for t in tools if t.name not in flagged]
    return "approved", None


async def build_report(tools: list[Tool], *, cfg: ScanConfig, declared: list[str], source_files: dict[str, str] | None,
                       other_servers: dict[str, list[str]], reserved: set[str] | None = None) -> dict[str, Any]:
    if len(tools) > MAX_TOOLS:
        raise ValueError(f"a server may expose at most {MAX_TOOLS} tools")
    findings: list[Finding] = []
    findings += await scan_descriptions(tools, cfg)
    findings += check_names(tools, other_servers, reserved)
    cap_findings, caps = review_capabilities(tools, declared)
    findings += cap_findings
    if source_files:
        findings += analyze_source(source_files)
    verdict, allowed = recommend(findings, tools)
    fp = fingerprint(tools)
    ran = {"tool_descriptions", "tool_names", "capabilities", "fingerprint"} | ({"source"} if source_files else set())
    return {
        "recommended_verdict": verdict, "recommended_allowed_tools": allowed, "fingerprint": fp.hex(),
        "findings": [f.as_dict() for f in findings], "capabilities": caps, "tool_count": len(tools),
        "checks": [{"id": cid, "name": name, "ran": cid in ran} for cid, name in CHECKS],
        "limitations": ["The sandbox run is not implemented: nothing here proves how the server behaves when called."]
                       + ([] if source_files else ["No source files were provided, so the code itself was not checked."]),
    }
