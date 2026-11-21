"""Posture scan (plan section 8): findings and score on risky and wired configs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from admit import cli
from admit.init import apply_plan, plan_init
from admit.posture import Finding, scan, scan_harness, score

REPO_ROOT = Path(__file__).resolve().parents[1]
RISKY = REPO_ROOT / "demo-repo" / "sample-risky-settings.json"


@pytest.fixture(autouse=True)
def fake_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return home


def _checks(findings: list[Finding]) -> list[tuple[str, str]]:
    return sorted((f.check, f.severity) for f in findings)


def test_sample_risky_settings() -> None:
    findings = scan(RISKY)
    checks = _checks(findings)
    assert checks.count(("mcp-bypass", "high")) == 4
    assert ("shell-server", "high") in checks
    assert checks.count(("broad-fs-root", "high")) == 2
    assert ("plaintext-secret", "high") in checks
    assert ("builtins-unchecked", "high") in checks
    assert score(findings) == 0
    # The secret value is never echoed.
    assert not any("ghp_" in f.detail for f in findings)


def _write(path: Path, data: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_hook_without_timeout_is_med(tmp_path: Path) -> None:
    path = _write(
        tmp_path / ".gemini" / "settings.json",
        {"hooks": {"BeforeTool": [{"matcher": ".*", "hooks": [
            {"type": "command", "command": "admit hook --harness gemini"}]}]}},
    )
    findings = scan(path)
    assert _checks(findings) == [("hook-no-timeout", "med")]
    assert score(findings) == 90


def test_builtins_off_without_hook_is_med(tmp_path: Path) -> None:
    path = _write(tmp_path / ".gemini" / "settings.json", {"tools": {"core": []}})
    assert _checks(scan(path)) == [("hook-missing", "med")]


def test_admit_server_without_pins_is_low(tmp_path: Path) -> None:
    path = _write(
        tmp_path / ".mcp.json",
        {"mcpServers": {"admit": {"type": "http", "url": "http://127.0.0.1:8765/mcp",
                                  "headers": {"Authorization": "Bearer ${ADMIT_TOKEN}"}}}},
    )
    assert _checks(scan(path)) == [("tools-not-pinned", "low")]
    (tmp_path / ".admit").mkdir()
    (tmp_path / ".admit" / "pins.json").write_text("{}", encoding="utf-8")
    assert scan(path) == []


def test_home_dir_and_folder_trust(tmp_path: Path, fake_home: Path) -> None:
    path = _write(
        tmp_path / "settings.json",
        {
            "security": {"folderTrust": {"enabled": False}},
            "mcpServers": {"fs": {"command": "npx", "args": ["server-filesystem", str(fake_home)]}},
        },
    )
    checks = _checks(scan(path))
    assert ("broad-fs-root", "high") in checks
    assert ("folder-trust-off", "low") in checks


def test_missing_harness_config_is_unchecked(tmp_path: Path) -> None:
    [finding] = scan_harness(tmp_path, "gemini")
    assert finding.check == "builtins-unchecked"


@pytest.mark.parametrize("harness", ["gemini", "antigravity", "claude"])
def test_wired_project_scores_100(tmp_path: Path, harness: str) -> None:
    assert score(scan_harness(tmp_path, harness)) == 70
    apply_plan(plan_init(tmp_path, [harness], python="/usr/bin/python3", npx=False))
    assert scan_harness(tmp_path, harness) == []
    assert scan(tmp_path) == []


def test_posture_cli(tmp_path: Path) -> None:
    result = CliRunner().invoke(cli.app, ["posture", str(RISKY)])
    assert result.exit_code == 0, result.output
    assert "score: 0/100" in result.output
    assert "plaintext-secret" in result.output
