"""The two runs differ only in these settings. Everything else (agent, tools, prompt, code path) is shared."""

from __future__ import annotations

import os

SHARED = {"DEMO_MODEL": "gpt-4.1", "DEMO_PROMPT": "Summarize my unread mail"}


def resolve(profile: str, environ: dict[str, str] | None = None) -> dict[str, str]:
    """`unprotected` talks to the model provider directly; `protected` talks to AgentShield, which forwards to the same provider."""
    e = os.environ if environ is None else environ
    if profile == "unprotected":
        return {**SHARED, "OPENAI_BASE_URL": e.get("DEMO_UNPROTECTED_BASE_URL", "http://127.0.0.1:9100/v1"),
                "OPENAI_API_KEY": e.get("DEMO_UNPROTECTED_API_KEY", "sk-demo-not-a-real-key")}
    if profile == "protected":
        return {**SHARED, "OPENAI_BASE_URL": e.get("DEMO_PROTECTED_BASE_URL", "http://127.0.0.1:8000/v1"),
                "OPENAI_API_KEY": e.get("DEMO_PROTECTED_API_KEY", "")}
    raise ValueError(f"unknown profile {profile!r}")
