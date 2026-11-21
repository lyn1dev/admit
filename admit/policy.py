"""Policy engine: load Kyverno-shaped YAML, compile CEL, decide.

Pure functions, no MCP and no model calls, so everything is unit-testable.
The Red Team agent calls `evaluate` directly to test bypass candidates.
"""

from __future__ import annotations

from pathlib import Path

from admit.types import Decision, Mode, ToolRequest


def load_policies(paths: list[Path]) -> list:
    """Parse and compile every policy; raise on any error (fail closed at startup)."""
    raise NotImplementedError


def evaluate(request: ToolRequest, policies: list, mode: Mode = Mode.ENFORCE) -> Decision:
    """Default-deny; any evaluation error returns DENY."""
    raise NotImplementedError
