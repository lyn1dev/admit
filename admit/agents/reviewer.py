"""Reviewer agent, ADK: advisory JSON verdict for WARN calls.

Input: caller, tool, argument keys and truncated values -- never file
contents or tool output. Output strict JSON
``{recommendation, risk, reason<=200}``. Advisory only: never approves.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Review:
    """Reviewer output for a held WARN call."""

    recommendation: str  # "approve" | "deny"
    risk: str  # "low" | "med" | "high"
    reason: str  # <= 200 characters


def review(caller: str, tool: str, args_summary: dict[str, str]) -> Review:
    """Advisory verdict for a WARN call. Never sees file contents or tool output."""
    raise NotImplementedError
