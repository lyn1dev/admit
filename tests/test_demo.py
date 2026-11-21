"""`admit demo`: tamper beat, replay verdicts, model on the dashboard, key never printed."""

from __future__ import annotations

import asyncio
import io
import json
import socket
from pathlib import Path

from rich.console import Console

from admit.audit import AuditLog, verify
from admit.config import AdmitConfig
from admit.dashboard import DashboardSink, event_stream
from admit.decision import DecisionPoint, NullAudit
from admit.demo import REPLAY_MODEL, REPLAY_SEQUENCE, Demo, tamper_copy
from admit.policy import load_policies
from admit.types import Decision, Mode, ToolRequest, Verdict

ROOT = Path(__file__).resolve().parents[1]


def _console() -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    return Console(file=buf, width=200, force_terminal=False, color_system=None), buf


def _decision_point(sink: object) -> DecisionPoint:
    config = AdmitConfig(callers={"dev-token": "coding-agent"}, mode=Mode.ENFORCE)
    policies = load_policies([ROOT / "policies" / "baseline.yaml"])
    return DecisionPoint(config, policies, NullAudit(), sink, workspace=ROOT / "demo-repo")


class _Sink:
    def __init__(self) -> None:
        self.events: list = []

    def publish(self, event: object) -> None:
        self.events.append(event)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------------- beat 4


def test_tamper_copy_breaks_copy_and_leaves_original_verifying(tmp_path: Path) -> None:
    log = AuditLog(directory=tmp_path / "audit", keys_dir=tmp_path / "keys")
    for i in range(3):
        log.append(
            ToolRequest("coding-agent", "shell.run", {"command": f"cmd {i}"}),
            Decision(Verdict.DENY, "shell-allowlist", "Command is not on the shell allowlist"),
        )
    log.close()
    assert verify(log.path) == (True, "OK (3 entries, signature valid)")

    copy, edit = tamper_copy(log.path, tmp_path / "tamper-demo")

    assert copy != log.path
    assert copy.with_suffix(".sig").is_file()
    assert edit == "entry 2: decision DENY -> ALLOW"
    assert verify(copy) == (False, "chain broken at entry 2")
    assert verify(log.path) == (True, "OK (3 entries, signature valid)")
    second = json.loads(log.path.read_text(encoding="utf-8").splitlines()[1])
    assert second["decision"] == "DENY"


def test_beat4_reports_broken_copy_and_ok_live(tmp_path: Path) -> None:
    log = AuditLog(directory=tmp_path / ".admit" / "audit", keys_dir=tmp_path / "keys")
    for _ in range(2):
        log.append(ToolRequest("coding-agent", "shell.run", {}), Decision(Verdict.ALLOW, "p", "r"))
    log.close()
    console, buf = _console()
    assert Demo(tmp_path, console).beat4() is True
    out = buf.getvalue()
    assert "chain broken at entry 2" in out
    assert "OK (2 entries, signature valid)" in out


# --------------------------------------------------------------------------- beat 1 replay


def test_replay_sequence_verdicts_against_baseline() -> None:
    dp = _decision_point(_Sink())

    async def run() -> list[Verdict]:
        verdicts = []
        for tool, args in REPLAY_SEQUENCE:
            decision = await dp.decide(ToolRequest("coding-agent", tool, args, REPLAY_MODEL))
            verdicts.append(decision.verdict)
        return verdicts

    verdicts = asyncio.run(run())
    summary = [
        (args.get("command") or args.get("path"), v.value)
        for (_, args), v in zip(REPLAY_SEQUENCE, verdicts, strict=True)
    ]
    assert summary == [
        ("README.md", "ALLOW"),
        (
            "pip install -r requirements.txt && python scripts/bootstrap.py && python -m pytest",
            "DENY",
        ),
        ("python scripts/bootstrap.py", "DENY"),
        ("pip install -r requirements.txt", "ALLOW"),
        ("python -m pytest", "ALLOW"),
        (".fixtures/eur_rates.json", "DENY"),
        ("tests/test_rates.py", "DENY"),
    ]


# --------------------------------------------------------------------------- model on cards


def test_event_model_flows_into_sse_message() -> None:
    sink = DashboardSink()
    dp = _decision_point(sink)
    request = ToolRequest(
        "coding-agent", "shell.run", {"command": "python scripts/bootstrap.py"}, REPLAY_MODEL
    )

    async def run() -> dict:
        await dp.decide(request)
        stream = event_stream(sink)
        try:
            first = await anext(stream)
        finally:
            await stream.aclose()
        assert first.startswith("data: ")
        return json.loads(first[len("data: ") :])

    msg = asyncio.run(run())
    assert msg["model"] == "gemini/gemini-3.5-flash-lite"
    assert msg["verdict"] == "DENY"
    assert msg["summary"] == "python scripts/bootstrap.py"


def test_event_model_defaults_empty() -> None:
    sink = _Sink()
    dp = _decision_point(sink)
    asyncio.run(dp.decide(ToolRequest("coding-agent", "fs.read_text_file", {"path": "README.md"})))
    assert sink.events[0].model == ""


# --------------------------------------------------------------------------- beat 0


def test_preflight_never_prints_the_key(tmp_path: Path, monkeypatch) -> None:
    secret = "AIzaFAKE-demo-secret-0123456789"
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    (tmp_path / ".env").write_text(f"GEMINI_API_KEY={secret}\n", encoding="utf-8")
    (tmp_path / "demo-repo" / ".fixtures").mkdir(parents=True)
    console, buf = _console()

    Demo(tmp_path, console, port=_free_port()).preflight(start=False, redteam=False)

    out = buf.getvalue()
    assert secret not in out
    assert "GEMINI_API_KEY present (not shown)" in out
    assert not (tmp_path / "demo-repo" / ".fixtures").exists()
    assert (tmp_path / ".admit" / "hook-token").read_text(encoding="utf-8") == (
        "dev-token-coding-agent"
    )


def test_unknown_step_is_an_error(tmp_path: Path) -> None:
    from admit.demo import run

    console, buf = _console()
    assert run("9", root=tmp_path, console=console) == 2
    assert "unknown step" in buf.getvalue()


# --------------------------------------------------------------------------- hook model


def test_gemini_hook_takes_model_from_admit_model_env(monkeypatch) -> None:
    from admit import hook

    sent: list[dict] = []

    def fake_post(url: str, token: str, body: dict) -> dict:
        sent.append(body)
        return {"allowed": True, "decision": "ALLOW"}

    monkeypatch.setattr(hook, "post_check", fake_post)
    monkeypatch.setattr(hook, "find_token", lambda cwd=None: "t")
    payload = {"tool_name": "run_shell_command", "tool_input": {"command": "pytest"}}

    monkeypatch.setenv("ADMIT_MODEL", "gemini-3.5-flash-lite")
    hook.decide("gemini", payload, "http://x", None)
    monkeypatch.delenv("ADMIT_MODEL")
    hook.decide("gemini", payload, "http://x", None)
    hook.decide("gemini", {**payload, "model": "gemini/explicit"}, "http://x", None)

    assert [b["model"] for b in sent] == ["gemini/gemini-3.5-flash-lite", "", "gemini/explicit"]
