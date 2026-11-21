"""Built-in self-protection: path resolution and always-on deny rules."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from admit.selfprotect import POLICY_NAME, check, resolve_path
from admit.types import Decision, ToolRequest, Verdict


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    return tmp_path


def _request(tool: str, **args: object) -> ToolRequest:
    return ToolRequest("coding-agent", tool, dict(args))


def _denied(decision: Decision | None, *, mentions: str) -> None:
    assert decision is not None, "expected a self-protection denial"
    assert decision.verdict is Verdict.DENY
    assert decision.policy == POLICY_NAME
    assert mentions in decision.reason
    assert decision.allowed is False


# -- writes -----------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        ".agents/hooks.json",
        "policies/x.yaml",
        "./ADMIT.YAML",
        "sub/../.gemini/settings.json",
        ".admit/hook-token",
        "admit.yaml",
        ".claude/settings.json",
        ".pi/mcp.json",
    ],
)
def test_protected_writes_are_denied(workspace: Path, path: str) -> None:
    _denied(check(_request("fs.write_file", path=path), workspace), mentions="may not write")


def test_absolute_write_inside_the_workspace_admit_dir_is_denied(workspace: Path) -> None:
    target = str(workspace / ".admit" / "audit" / "session.jsonl")
    _denied(check(_request("fs.write_file", path=target), workspace), mentions="may not write")


def test_global_harness_config_write_is_denied(workspace: Path) -> None:
    for path in ("~/.gemini/config/hooks.json", "~/.gemini/antigravity-cli/settings.json"):
        _denied(check(_request("fs.write_file", path=path), workspace), mentions="may not write")


def test_move_source_and_destination_are_both_checked(workspace: Path) -> None:
    request = _request("fs.move", source="src/app.py", destination=".agents/hooks.json")
    _denied(check(request, workspace), mentions="may not write")


def test_path_lists_are_checked(workspace: Path) -> None:
    request = _request("fs.write_file", paths=["src/app.py", "policies/baseline.yaml"])
    _denied(check(request, workspace), mentions="may not write")


def test_write_verb_in_a_bare_tool_name_counts_as_a_write(workspace: Path) -> None:
    _denied(
        check(_request("custom.edit_thing", path="policies/x.yaml"), workspace),
        mentions="may not write",
    )
    _denied(
        check(_request("builtin.sed_file", path=".gemini/settings.json"), workspace),
        mentions="may not write",
    )


@pytest.mark.skipif(os.name != "nt", reason="case-insensitive matching is a Windows rule")
def test_writes_are_case_insensitive_on_windows(workspace: Path) -> None:
    _denied(
        check(_request("fs.write_file", path="POLICIES/X.YAML"), workspace),
        mentions="may not write",
    )


# -- reads ------------------------------------------------------------------


@pytest.mark.parametrize("path", [".env", ".env.local", "sub/.env", "sub/.env.production"])
def test_dotenv_reads_are_denied(workspace: Path, path: str) -> None:
    _denied(check(_request("fs.read_text_file", path=path), workspace), mentions=".env")


def test_audit_key_reads_are_denied(workspace: Path) -> None:
    _denied(
        check(_request("fs.read_text_file", path=".admit/keys/session.key"), workspace),
        mentions=".admit/keys",
    )


def test_listing_the_keys_directory_is_denied(workspace: Path) -> None:
    _denied(
        check(_request("fs.list_directory", path=".admit/keys"), workspace),
        mentions="may not read",
    )
    _denied(check(_request("fs.search_files", path=".env.d"), workspace), mentions="may not read")


def test_safe_reads_and_writes_are_not_self_protected(workspace: Path) -> None:
    assert check(_request("fs.read_text_file", path="src/app.py"), workspace) is None
    assert check(_request("fs.list_directory", path="src"), workspace) is None
    assert check(_request("fs.write_file", path="src/app.py", content="hi"), workspace) is None
    assert check(_request("fs.edit_file", path="sub/../src/app.py"), workspace) is None


def test_shell_run_is_not_path_checked(workspace: Path) -> None:
    # ADR-0004: only the exact-command allowlist protects protected paths here.
    assert check(_request("shell.run", command="type .env"), workspace) is None
    assert check(_request("shell.run", command="rm .agents/hooks.json"), workspace) is None


def test_unknown_tool_without_paths_is_not_self_protected(workspace: Path) -> None:
    assert check(_request("net.fetch", url="https://x.test"), workspace) is None


def test_unresolvable_path_fails_closed(workspace: Path) -> None:
    _denied(check(_request("fs.write_file", path=123), workspace), mentions="cannot resolve")
    _denied(check(_request("fs.read_text_file", path="   "), workspace), mentions="cannot resolve")


# -- path resolution --------------------------------------------------------


def test_relative_paths_join_the_workspace(workspace: Path) -> None:
    assert resolve_path("src/app.py", workspace) == resolve_path(
        str(workspace / "src" / "app.py"), workspace
    )


def test_parent_segments_are_normalised(workspace: Path) -> None:
    assert resolve_path("sub/../src/app.py", workspace) == resolve_path("src/app.py", workspace)


def test_both_slash_styles_are_accepted(workspace: Path) -> None:
    assert resolve_path("src/app.py", workspace) == resolve_path("src\\app.py", workspace)


def test_home_is_expanded(workspace: Path) -> None:
    expected = Path(os.path.realpath(os.path.expanduser("~/.gemini/config/hooks.json")))
    assert resolve_path("~/.gemini/config/hooks.json", workspace) == expected


def test_resolution_is_absolute(workspace: Path) -> None:
    assert resolve_path(".env", workspace).is_absolute()
    assert resolve_path(".env", workspace) == Path(os.path.realpath(workspace)) / ".env"


def test_symlinks_are_resolved(workspace: Path) -> None:
    real = workspace / "real"
    real.mkdir()
    link = workspace / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks needs privileges on this machine")
    assert resolve_path("link/x.txt", workspace) == resolve_path("real/x.txt", workspace)
    _denied(
        check(_request("fs.write_file", path="link/../.agents/hooks.json"), workspace),
        mentions="may not write",
    )
