"""Framework smoke tests: every admit module imports and the CLI matches the plan."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from admit import cli

MODULES = [
    "admit",
    "admit.audit",
    "admit.config",
    "admit.dashboard",
    "admit.hook",
    "admit.init",
    "admit.pins",
    "admit.posture",
    "admit.policy",
    "admit.proxy",
    "admit.redact",
    "admit.server",
    "admit.selfprotect",
    "admit.trie",
    "admit.agents.author",
    "admit.agents.llm",
    "admit.agents.redteam",
    "admit.agents.reviewer",
    "admit.servers.shell",
]


@pytest.mark.parametrize("module", MODULES)
def test_every_module_imports(module: str) -> None:
    __import__(module)


def test_cli_help_lists_all_eight_commands() -> None:
    runner = CliRunner()
    result = runner.invoke(cli.app, ["--help"])
    assert result.exit_code == 0
    help_text = result.output
    for command in ["init", "serve", "hook", "verify", "posture", "learn", "redteam", "demo"]:
        assert command in help_text


def test_hook_maps_cover_run_command_and_run_shell_command() -> None:
    from admit.hook import ANTIGRAVITY_TOOL_MAP, GEMINI_TOOL_MAP

    assert "run_command" in ANTIGRAVITY_TOOL_MAP
    assert "run_shell_command" in GEMINI_TOOL_MAP


def test_posture_score_is_trivial_and_floors_at_zero() -> None:
    from admit.posture import SEVERITY_PENALTY, Finding, score

    findings = [
        Finding(
            severity="high", check="shell-without-admit", detail="shell reachable without Admit"
        ),
        Finding(severity="high", check="plaintext-secret", detail="ghp_ in headers"),
        Finding(
            severity="med",
            check="hook-missing-timeout",
            detail="Admit hook with no explicit timeout",
        ),
        Finding(severity="low", check="pins-missing", detail=".admit/pins.json missing"),
    ]
    expected = max(0, 100 - sum(SEVERITY_PENALTY[f.severity] for f in findings))
    assert score(findings) == expected
