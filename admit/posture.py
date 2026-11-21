"""Static scan of an agent MCP config for risky settings.

No network and no model calls: one :class:`Finding` per check, then
:func:`score` out of 100 (100 minus penalties, floored at 0).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SEVERITY_PENALTY = {"high": 30, "med": 10, "low": 3}


@dataclass(frozen=True)
class Finding:
    """One posture finding."""

    severity: str  # "high" | "med" | "low"
    check: str
    detail: str


def scan(config_path: Path) -> list[Finding]:
    """Scan an agent MCP config (e.g. .gemini/settings.json) for risky settings."""
    raise NotImplementedError


def score(findings: list[Finding]) -> int:
    """100 minus per-severity penalties, floored at 0 (trivial; implemented here)."""
    penalty = sum(SEVERITY_PENALTY.get(finding.severity, 0) for finding in findings)
    return max(0, 100 - penalty)
