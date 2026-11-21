"""``admit init <harness>``: route a harness through Admit, move upstreams into admit.yaml.

Writes the harness adapter config (``.agents/hooks.json`` for Antigravity,
``.gemini/settings.json`` for Gemini CLI, ``.mcp.json`` for Claude Code,
``.pi/extensions`` for Pi), ``admit.yaml`` with the generated token, removes
upstreams from the agent's config, installs the hook, and runs posture before
and after.
"""

from __future__ import annotations

from pathlib import Path

SUPPORTED_HARNESSES: frozenset[str] = frozenset(
    {"antigravity", "gemini", "claude", "pi", "mcp"}
)


def init_harness(harness: str, workspace: Path, print_only: bool = False) -> None:
    """Wire ``harness`` into Admit at ``workspace``.

    ``print_only`` prints the adapter snippet (``init --print``) without
    writing anything.
    """
    raise NotImplementedError
