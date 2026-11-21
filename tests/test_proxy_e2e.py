"""End-to-end gateway: bearer token, decision path, redaction, pins.

One real upstream (``admit.servers.shell``, launched over stdio by Admit) and an
in-memory FastMCP client. No network, no npx, no API keys.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from admit.config import AdmitConfig, Upstream
from admit.decision import DecisionPoint, NullAudit
from admit.pins import load_pins, save_pins
from admit.proxy import build_gateway
from admit.types import Decision, Event, Mode, ToolRequest, Verdict


def _no_self_protection(request: ToolRequest, workspace: Path) -> Decision | None:
    """admit.selfprotect is still a stub; the gateway must still be testable."""
    return None

REPO_ROOT = Path(__file__).resolve().parents[1]
TOKEN = "dev-token"
CALLER = "coding-agent"

# The exact commands this "policy" lets through (see policies/baseline.yaml).
SET_COMMAND = "set" if os.name == "nt" else "env"


class RecordingSink:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def publish(self, event: Event) -> None:
        self.events.append(event)


def _is_allowed(command: str) -> bool:
    if command == SET_COMMAND:
        return True
    return command.startswith("echo ") and not any(ch in command for ch in ">|&;`$")


def _evaluate(request: ToolRequest, policies: list, mode: Mode) -> Decision:
    if request.tool != "shell.run":
        return Decision(Verdict.DENY, None, "default deny: tool is not in any policy")
    command = str(request.args.get("command", ""))
    if _is_allowed(command):
        return Decision(Verdict.ALLOW, "shell-allowlist", "command is on the allowlist")
    return Decision(
        Verdict.DENY, "shell-allowlist", "Command is not on the shell allowlist"
    )


def _config(tmp_path: Path) -> AdmitConfig:
    return AdmitConfig(
        callers={TOKEN: CALLER},
        upstreams={
            "shell": Upstream(
                command=sys.executable,
                args=["-m", "admit.servers.shell", "--cwd", str(tmp_path)],
                # The child must import `admit`, so it runs from the repo root.
                cwd=str(REPO_ROOT),
            )
        },
    )


def _gateway(tmp_path: Path, **kwargs: Any) -> tuple[Any, DecisionPoint, RecordingSink]:
    config = _config(tmp_path)
    sink = RecordingSink()
    decision_point = DecisionPoint(
        config, [], NullAudit(), sink, workspace=tmp_path,
        evaluate=_evaluate,
        self_protect=_no_self_protection,
    )
    gateway = build_gateway(
        config,
        decision_point,
        token_getter=lambda: f"Bearer {TOKEN}",
        **kwargs,
    )
    return gateway, decision_point, sink


@pytest.mark.asyncio
async def test_unknown_token_is_rejected_without_calling_upstream(tmp_path: Path) -> None:
    config = _config(tmp_path)
    decision_point = DecisionPoint(
        config, [], NullAudit(), RecordingSink(), workspace=tmp_path,
        evaluate=_evaluate,
        self_protect=_no_self_protection,
    )
    gateway = build_gateway(
        config, decision_point, token_getter=lambda: "Bearer not-a-real-token"
    )
    marker = tmp_path / "should-not-exist.txt"
    async with Client(gateway) as client:
        result = await client.call_tool_mcp(
            "shell_run", {"command": f"echo hi > {marker}"}
        )
    assert result.is_error is True
    assert result.structured_content["admit"]["reason"].startswith("unauthorized")
    assert not marker.exists()


@pytest.mark.asyncio
async def test_allowed_command_is_forwarded(tmp_path: Path) -> None:
    gateway, _, sink = _gateway(tmp_path)
    async with Client(gateway) as client:
        result = await client.call_tool_mcp("shell_run", {"command": "echo hello admit"})
    assert result.is_error is not True
    assert "hello admit" in result.content[0].text
    assert [event.verdict for event in sink.events] == [Verdict.ALLOW]
    assert sink.events[0].tool == "shell.run"


@pytest.mark.asyncio
async def test_denied_command_never_runs(tmp_path: Path) -> None:
    gateway, _, sink = _gateway(tmp_path)
    marker = tmp_path / "pwned.txt"
    async with Client(gateway) as client:
        result = await client.call_tool_mcp(
            "shell_run", {"command": f"echo pwned > {marker}"}
        )
    assert result.is_error is True
    payload = result.structured_content["admit"]
    assert payload["decision"] == "DENY"
    assert payload["policy"] == "shell-allowlist"
    assert payload["hint"]
    assert not marker.exists()
    assert [event.verdict for event in sink.events] == [Verdict.DENY]


@pytest.mark.asyncio
async def test_secret_in_output_is_redacted_and_counted(tmp_path: Path) -> None:
    gateway, _, _ = _gateway(tmp_path)
    async with Client(gateway) as client:
        result = await client.call_tool_mcp(
            "shell_run", {"command": "echo sk_test_FAKE_DO_NOT_USE_0000000000"}
        )
    assert result.is_error is not True
    assert "[REDACTED]" in result.content[0].text
    assert "sk_test_FAKE_DO_NOT_USE_0000000000" not in result.content[0].text
    assert result.structured_content["stdout"].strip() == "[REDACTED]"
    assert result.structured_content["redacted"] == 1
    assert any(
        item.text == "admit: redacted 1 secret(s)"
        for item in result.content
        if getattr(item, "type", None) == "text"
    )


@pytest.mark.asyncio
async def test_upstream_environment_is_scrubbed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ADMIT_TEST_SECRET", "leak")
    monkeypatch.setenv("GOOGLE_API_KEY", "leak")
    gateway, _, _ = _gateway(tmp_path)
    async with Client(gateway) as client:
        result = await client.call_tool_mcp("shell_run", {"command": SET_COMMAND})
    assert result.is_error is not True
    dumped = result.content[0].text.lower()
    assert "leak" not in dumped
    assert "admit_test_secret" not in dumped
    assert "google_api_key" not in dumped
    # ... while the allowlisted OS variables still arrive, or nothing would run.
    assert "path" in dumped


@pytest.mark.asyncio
async def test_pins_hide_and_deny_a_changed_tool(tmp_path: Path) -> None:
    pins_path = tmp_path / "pins.json"
    gateway, _, sink = _gateway(tmp_path, pins_path=pins_path)

    async with Client(gateway) as client:
        names = [tool.name for tool in await client.list_tools()]
    assert names == ["shell_run"]
    assert load_pins(pins_path)  # first serve records every tool

    tampered = load_pins(pins_path)
    tampered["shell_run"] = "0" * 64
    save_pins(pins_path, tampered)

    async with Client(gateway) as client:
        names = [tool.name for tool in await client.list_tools()]
        result = await client.call_tool_mcp("shell_run", {"command": "echo hi"})
    assert names == []  # the changed tool is not advertised at all
    assert result.is_error is True
    assert result.structured_content["admit"]["decision"] == "PIN_MISMATCH"
    assert any(event.verdict is Verdict.PIN_MISMATCH for event in sink.events)


@pytest.mark.asyncio
async def test_pin_flag_reapproves(tmp_path: Path) -> None:
    pins_path = tmp_path / "pins.json"
    gateway, _, _ = _gateway(tmp_path, pins_path=pins_path)
    async with Client(gateway) as client:
        await client.list_tools()
    tampered = load_pins(pins_path)
    tampered["shell_run"] = "0" * 64
    save_pins(pins_path, tampered)

    reapproving, _, _ = _gateway(tmp_path, pins_path=pins_path, pin=True)
    async with Client(reapproving) as client:
        names = [tool.name for tool in await client.list_tools()]
        result = await client.call_tool_mcp("shell_run", {"command": "echo hi"})
    assert names == ["shell_run"]
    assert result.is_error is not True
    assert load_pins(pins_path)["shell_run"] != "0" * 64
