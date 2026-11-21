"""admit.yaml loading: the repo config, overrides for env vars, fail-closed errors."""

from __future__ import annotations

from pathlib import Path

import pytest

from admit.config import load_config
from admit.types import Mode

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_repo_admit_yaml_loads() -> None:
    config = load_config(REPO_ROOT / "admit.yaml")
    assert config.mode is Mode.ENFORCE
    assert config.port == 8765
    assert config.callers["dev-token-coding-agent"] == "coding-agent"
    assert config.callers["dev-token-ci-bot"] == "ci-bot"
    assert config.warn_timeout_seconds == 60
    assert set(config.upstreams) == {"fs", "shell"}
    shell = config.upstreams["shell"]
    assert shell.command == "uv"
    assert shell.args[-2:] == ["--cwd", "demo-repo"]
    assert config.upstreams["fs"].command == "npx"
    assert config.policies == [Path("policies/baseline.yaml")]


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not found"):
        load_config(tmp_path / "nope.yaml")


def test_unknown_mode_raises(tmp_path: Path) -> None:
    path = tmp_path / "admit.yaml"
    path.write_text("mode: pretend\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unknown mode"):
        load_config(path)


def test_missing_upstream_command_raises(tmp_path: Path) -> None:
    path = tmp_path / "admit.yaml"
    path.write_text(
        "mode: enforce\nupstreams:\n  fs:\n    args: ['-y']\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="missing 'command'"):
        load_config(path)


def test_non_string_caller_raises(tmp_path: Path) -> None:
    path = tmp_path / "admit.yaml"
    path.write_text("callers:\n  tok: 7\n", encoding="utf-8")
    with pytest.raises(ValueError, match="callers.tok"):
        load_config(path)


def test_env_values_expand_from_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN_VALUE", "ghp_from_admit_env")
    path = tmp_path / "admit.yaml"
    path.write_text(
        "upstreams:\n"
        "  gh:\n"
        "    command: npx\n"
        "    args: ['-y', 'server']\n"
        "    env:\n"
        "      GITHUB_PERSONAL_ACCESS_TOKEN: ${GITHUB_TOKEN_VALUE}\n"
        "      PLAIN: literal\n",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.upstreams["gh"].env == {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_from_admit_env",
        "PLAIN": "literal",
    }


def test_unset_env_variable_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADMIT_DEFINITELY_UNSET", raising=False)
    path = tmp_path / "admit.yaml"
    path.write_text(
        "upstreams:\n  gh:\n    command: npx\n    env:\n      TOKEN: ${ADMIT_DEFINITELY_UNSET}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="ADMIT_DEFINITELY_UNSET"):
        load_config(path)


def test_environment_is_not_expanded_in_args(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DEMO", "demo-repo")
    path = tmp_path / "admit.yaml"
    path.write_text(
        "upstreams:\n  fs:\n    command: npx\n    args: ['-y', '${DEMO}']\n", encoding="utf-8"
    )
    assert load_config(path).upstreams["fs"].args == ["-y", "${DEMO}"]


def test_audit_mode_and_port_are_read(tmp_path: Path) -> None:
    path = tmp_path / "admit.yaml"
    path.write_text(
        "mode: audit\nport: 9000\nwarn:\n  timeout_seconds: 5\n", encoding="utf-8"
    )
    config = load_config(path)
    assert config.mode is Mode.AUDIT
    assert config.port == 9000
    assert config.warn_timeout_seconds == 5
    assert config.policies == [Path("policies/baseline.yaml")]
