"""The AI service catalog and the heuristics for AI-looking hosts that are not in it."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

import yaml

# Paths that only model APIs use. A host with one of these is "AI-looking" even if nobody has catalogued it.
MODEL_API_PATHS = re.compile(r"/(?:v1/(?:chat/completions|completions|messages|embeddings|responses)|api/(?:generate|chat)|openai/deployments/[^/]+/(?:chat|completions|embeddings)|v1beta/models/[^/]+:(?:generateContent|streamGenerateContent))(?:$|[/?])", re.I)
LARGE_UPLOAD_BYTES = 1_000_000


@dataclass(frozen=True)
class Service:
    domain: str
    vendor: str
    category: str
    risk: str


@dataclass(frozen=True)
class Match:
    domain: str                 # the domain the inventory row is kept under
    vendor: str | None
    category: str | None
    risk: str
    reason: str                 # "catalog" or "heuristic: model API path"


@lru_cache
def services() -> dict[str, Service]:
    data = yaml.safe_load((resources.files("agentshield.shadow") / "catalog.yaml").read_text(encoding="utf-8"))
    return {s["domain"]: Service(s["domain"], s["vendor"], s["category"], s["risk"]) for s in data["services"]}


def registrable(host: str) -> str:
    """The host without a port, lower-case, no trailing dot."""
    return host.strip().lower().rstrip(".").split(":")[0]


def classify_host(host: str, path: str = "") -> Match | None:
    """Catalog first (the host or any parent domain), then the model-API path heuristic. None for everything else."""
    h = registrable(host)
    if not h or "." not in h:
        return None
    cat = services()
    parts = h.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in cat:
            s = cat[cand]
            return Match(s.domain if s.domain == h or h.endswith("." + s.domain) and s.domain.count(".") >= 2 else s.domain, s.vendor, s.category, s.risk, "catalog")
    if path and MODEL_API_PATHS.search(path):
        return Match(h, None, "api", "high", "heuristic: the path is a model API")
    return None


def suggested_alternative(match: Match) -> str:
    return (f"Use the company's AgentShield-routed model instead of {match.vendor or match.domain} ({match.domain}). "
            "Approved tools get a connection snippet that sends their traffic through the gateway, where policy, scanning and the audit log apply.")
