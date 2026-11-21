"""``admit init``: detection, hook config shapes, merging, idempotence, non-TTY path."""

from __future__ import annotations

import io
import json
import shutil
from pathlib import Path

import pytest
import yaml
from rich.console import Console
from typer.testing import CliRunner

from admit import cli
from admit import init as init_mod
from admit.config import load_config
from admit.init import (
    Harness,
    apply_plan,
    detect,
    hook_command,
    pick,
    plan_init,
    render_picker,
    run_init,
)
from admit.types import Mode

PY = "/opt/py/bin/python3"


@pytest.fixture(autouse=True)
def isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Fake home, no real harness binaries, no slow --version calls."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setattr(init_mod.shutil, "which", lambda name: None)
    monkeypatch.setattr(init_mod, "_version", lambda exe: "1.0.0")
    return home


@pytest.fixture
def project(tmp_path: Path) -> Path:
    p = tmp_path / "proj"
    p.mkdir()
    return p


def _console() -> Console:
    return Console(file=io.StringIO(), width=120, color_system=None)


def _output(console: Console) -> str:
    return console.file.getvalue()  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- detection


def test_detect_nothing_installed(project: Path) -> None:
    found = {h.key: h for h in detect(project)}
    assert [h for h in found.values() if h.installed] == [found["mcp"]]
    assert not found["gemini"].installed


def test_detect_path_localappdata_and_home(
    project: Path, tmp_path: Path, isolate: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agy = tmp_path / "localappdata" / "agy" / "bin" / "agy.exe"
    agy.parent.mkdir(parents=True)
    agy.write_text("", encoding="utf-8")
    (isolate / ".pi").mkdir()
    monkeypatch.setattr(
        init_mod.shutil, "which", lambda name: "/bin/gemini" if name == "gemini" else None
    )
    found = {h.key: h for h in detect(project)}
    assert found["antigravity"].installed and found["antigravity"].path == str(agy)
    assert found["gemini"].installed and found["gemini"].version == "1.0.0"
    assert found["pi"].installed and found["pi"].path is None
    assert not found["claude"].installed


def test_detect_wired(project: Path) -> None:
    apply_plan(plan_init(project, ["gemini"], python=PY, npx=False))
    found = {h.key: h for h in detect(project, versions=False)}
    assert found["gemini"].wired
    assert not found["antigravity"].wired


def test_version_never_hangs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.undo()
    assert init_mod._version("definitely-not-a-real-binary-xyz") is None


# --------------------------------------------------------------------------- hook shapes


def test_hook_command_quoting() -> None:
    win = r"C:\Program Files\Py\python.exe"
    assert hook_command("antigravity", win, "nt") == f'"{win}" -I -m admit.hook antigravity'
    assert hook_command("gemini", win, "nt") == f'& "{win}" -I -m admit.hook gemini'
    assert hook_command("claude", win, "nt") == (
        '"C:/Program Files/Py/python.exe" -I -m admit.hook claude'
    )
    assert hook_command("gemini", "/a b/python", "posix") == "'/a b/python' -I -m admit.hook gemini"


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_gemini_shape(project: Path) -> None:
    apply_plan(plan_init(project, ["gemini"], python=PY, npx=False, os_name="posix"))
    assert _json(project / ".gemini" / "settings.json") == {
        "hooks": {"BeforeTool": [{"matcher": ".*", "hooks": [{
            "name": "admit", "type": "command",
            "command": f"{PY} -I -m admit.hook gemini", "timeout": 75000}]}]}
    }


def test_antigravity_shape(project: Path) -> None:
    apply_plan(plan_init(project, ["agy"], python=PY, npx=False, os_name="posix"))
    assert _json(project / ".agents" / "hooks.json") == {
        "admit": {"enabled": True, "PreToolUse": [{"matcher": "*", "hooks": [{
            "type": "command", "command": f"{PY} -I -m admit.hook antigravity",
            "timeout": 75}]}]}
    }


def test_claude_shape(project: Path) -> None:
    apply_plan(plan_init(project, ["claude"], python=PY, npx=False, os_name="posix"))
    assert _json(project / ".claude" / "settings.json") == {
        "hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [{
            "type": "command", "command": f"{PY} -I -m admit.hook claude", "timeout": 75}]}]}
    }


# --------------------------------------------------------------------------- merging


def test_merge_keeps_other_keys_and_backs_up(project: Path) -> None:
    settings = project / ".gemini" / "settings.json"
    settings.parent.mkdir()
    original = {
        "model": {"name": "gemini-3.5-flash-lite"},
        "hooks": {"BeforeTool": [{"matcher": "write_file", "hooks": [
            {"type": "command", "command": "lint"}]}],
            "AfterTool": [{"matcher": ".*", "hooks": []}]},
    }
    settings.write_text(json.dumps(original), encoding="utf-8")
    apply_plan(plan_init(project, ["gemini"], python=PY, npx=False))
    data = _json(settings)
    assert data["model"] == original["model"]
    assert data["hooks"]["AfterTool"] == original["hooks"]["AfterTool"]
    assert data["hooks"]["BeforeTool"][0] == original["hooks"]["BeforeTool"][0]
    assert len(data["hooks"]["BeforeTool"]) == 2
    backup = settings.with_name("settings.json.admit-backup")
    assert json.loads(backup.read_text(encoding="utf-8")) == original


def test_existing_admit_hook_updated_in_place(project: Path) -> None:
    repo_demo = Path(__file__).resolve().parents[1] / "demo-repo" / ".gemini" / "settings.json"
    target = project / ".gemini" / "settings.json"
    target.parent.mkdir()
    shutil.copy(repo_demo, target)
    apply_plan(plan_init(project, ["gemini"], python=PY, npx=False, os_name="posix"))
    data = _json(target)
    [group] = data["hooks"]["BeforeTool"]
    [entry] = group["hooks"]
    assert entry["command"] == f"{PY} -I -m admit.hook gemini"
    assert entry["description"]  # extra keys survive
    assert data["model"] == {"name": "gemini-3.5-flash-lite"}


def test_init_twice_changes_nothing(project: Path) -> None:
    harnesses = ["gemini", "antigravity", "claude", "mcp"]
    apply_plan(plan_init(project, harnesses, python=PY, npx=True))
    snapshot = {p: p.read_bytes() for p in project.rglob("*") if p.is_file()}
    second = plan_init(project, harnesses, python=PY, npx=True)
    assert second.changes == []
    apply_plan(second)
    assert {p: p.read_bytes() for p in project.rglob("*") if p.is_file()} == snapshot
    assert not list(project.rglob("*.admit-backup"))


# --------------------------------------------------------------------------- admit.yaml etc.


def test_token_gitignore_policies_and_config(project: Path) -> None:
    (project / ".gitignore").write_text("node_modules/", encoding="utf-8")
    plan = plan_init(project, ["gemini"], python=r"C:\Py 3\python.exe", npx=True)
    apply_plan(plan)
    token = (project / ".admit" / "hook-token").read_text(encoding="utf-8").strip()
    assert token == plan.token and len(token) >= 32
    assert (project / ".gitignore").read_text(encoding="utf-8") == "node_modules/\n.admit/\n"
    assert (project / "policies" / "baseline.yaml").is_file()

    config = load_config(project / "admit.yaml")
    assert config.mode is Mode.AUDIT
    assert config.callers == {token: "coding-agent"}
    shell = config.upstreams["shell"]
    assert shell.command == r"C:\Py 3\python.exe"
    assert shell.args == ["-m", "admit.servers.shell", "--cwd", str(project.resolve())]
    assert config.upstreams["fs"].command == "npx"
    assert config.policies == [Path("policies/baseline.yaml")]


def test_no_npx_no_fs_and_enforce(project: Path) -> None:
    apply_plan(plan_init(project, ["mcp"], python=PY, npx=False, enforce=True))
    config = load_config(project / "admit.yaml")
    assert set(config.upstreams) == {"shell"}
    assert config.mode is Mode.ENFORCE


def test_existing_admit_yaml_merged(project: Path) -> None:
    (project / "admit.yaml").write_text(
        "mode: audit\nport: 9000\ncallers:\n  other: ci-bot\n", encoding="utf-8"
    )
    (project / "policies").mkdir()
    plan = plan_init(project, ["gemini"], python=PY, npx=False)
    apply_plan(plan)
    raw = yaml.safe_load((project / "admit.yaml").read_text(encoding="utf-8"))
    assert raw["port"] == 9000
    assert raw["callers"] == {"other": "ci-bot", plan.token: "coding-agent"}
    assert "shell" in raw["upstreams"]
    assert (project / "admit.yaml.admit-backup").is_file()
    assert not (project / "policies" / "baseline.yaml").exists()  # own policies/ kept


# --------------------------------------------------------------------------- run_init / CLI


def test_non_tty_defaults_to_mcp_when_nothing_installed(project: Path) -> None:
    console = _console()
    assert run_init(project, console=console, interactive=False) == 0
    out = _output(console)
    assert '"Authorization": "Bearer' in out
    assert (project / ".admit" / "hook-token").is_file()
    assert "Next:" in out


def test_cli_harness_yes_and_dry_run(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(project)
    runner = CliRunner()
    dry = runner.invoke(cli.app, ["init", "--harness", "gemini", "--dry-run"])
    assert dry.exit_code == 0, dry.output
    assert "would create" in dry.output
    assert not (project / ".gemini").exists()

    result = runner.invoke(cli.app, ["init", "--harness", "gemini", "--yes"])
    assert result.exit_code == 0, result.output
    assert "Posture before: 70/100" in result.output
    assert "Posture after: 100/100" in result.output
    assert "gemini -p" in result.output
    assert (project / ".gemini" / "settings.json").is_file()

    again = runner.invoke(cli.app, ["init", "gemini"])
    assert "nothing to change" in again.output


def test_print_only_writes_nothing(project: Path) -> None:
    console = _console()
    assert run_init(project, ["gemini"], print_only=True, console=console) == 0
    assert list(project.iterdir()) == []
    assert "/mcp" in _output(console)


def test_unknown_harness(project: Path) -> None:
    assert run_init(project, ["vim"], console=_console()) == 2


def test_pi_only_is_coming_soon(project: Path) -> None:
    console = _console()
    assert run_init(project, ["pi"], console=console) == 0
    assert "coming soon" in _output(console)


# --------------------------------------------------------------------------- picker


def _harnesses() -> list[Harness]:
    return [
        Harness("antigravity", "Antigravity CLI (agy)", True, "agy", "1.5.14"),
        Harness("gemini", "Gemini CLI", True, "gemini", "0.70.0"),
        Harness("claude", "Claude Code", False),
        Harness("mcp", "Any MCP client (print snippet)", True),
    ]


def test_picker_keys() -> None:
    keys = iter(["down", "space", "down", "space", "down", "space", "enter"])
    # gemini toggled off, claude (not installed) ignored, mcp toggled on
    assert pick(_harnesses(), _console(), lambda: next(keys)) == ["antigravity", "mcp"]


def test_picker_cancel() -> None:
    assert pick(_harnesses(), _console(), lambda: "esc") is None


def test_picker_render() -> None:
    console = _console()
    console.print(render_picker(_harnesses(), 0, {"antigravity", "gemini"}))
    out = _output(console)
    assert "> [x] Antigravity CLI (agy)" in out
    assert "[ ] Claude Code" in out and "not installed" in out
