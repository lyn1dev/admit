"""Red Team agent + LoopAgent, ADK: bypass candidates tested via policy.evaluate.

Proposes malicious tool calls aimed at exfiltration and runs each directly
through ``policy.evaluate`` (no worker agent, near-zero quota), in a LoopAgent
with the Author patching and a checker re-running. Max ``MAX_ROUNDS`` rounds,
exits early when nothing gets through. Human approves the final diff; writes
``.admit/redteam-report.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

MAX_ROUNDS = 3


@dataclass
class RedteamReport:
    """Red Team output: bypasses found, rounds run, whether a patch landed."""

    bypasses_found: int
    rounds: int
    patched: bool
    report_path: Path


def run_redteam(policies: Path, max_rounds: int = MAX_ROUNDS) -> RedteamReport:
    """Attack ``policies`` directly via ``policy.evaluate``, up to max_rounds."""
    raise NotImplementedError
