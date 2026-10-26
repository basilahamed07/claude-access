"""Session risk arithmetic (arch §2.2): r' = 1 - (1 - r)(1 - 0.6 c) for suspicious/malicious content."""

from __future__ import annotations

VERDICT_WEIGHT = 0.6


def risk_amount(verdict: str, hostility: float) -> float:
    """How much one scan result adds to the session risk (0 for clean content)."""
    if verdict == "clean":
        return 0.0
    return VERDICT_WEIGHT * min(max(hostility, 0.0), 1.0)


def update_risk(current: float, verdict: str, confidence: float) -> float:
    amount = risk_amount(verdict, confidence)
    return min(1.0, 1 - (1 - current) * (1 - amount))


def bump(current: float, amount: float) -> float:
    return min(1.0, 1 - (1 - current) * (1 - min(max(amount, 0.0), 1.0)))
