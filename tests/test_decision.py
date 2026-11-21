"""The one decision path: fail-closed ordering, audit, events, token identity."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from admit.config import AdmitConfig
from admit.decision import (
    ConsoleSink,
    DecisionPoint,
    NullAudit,
    caller_for_token,
)
from admit.types import Decision, Event, Mode, ToolRequest, Verdict

WORKSPACE = Path("/workspace")


class RecordingAudit:
    def __init__(self, *, fail: bool = False) -> None:
        self.entries: list[tuple[ToolRequest, Decision]] = []
        self.fail = fail

    def append(self, request: ToolRequest, decision: Decision) -> dict:
        if self.fail:
            raise OSError("disk full")
        self.entries.append((request, decision))
        return {}

    def close(self) -> None:
        return None


class RecordingSink:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def publish(self, event: Event) -> None:
        self.events.append(event)


class ExplodingSink:
    def publish(self, event: Event) -> None:
        raise RuntimeError("console on fire")


def _config(**kwargs: Any) -> AdmitConfig:
    base = {"callers": {"dev-token": "coding-agent"}, "mode": Mode.ENFORCE}
    base.update(kwargs)
    return AdmitConfig(**base)


def _dp(
    *,
    evaluate: Any = None,
    self_protect: Any = None,
    audit: Any = None,
    sink: Any = None,
    config: AdmitConfig | None = None,
) -> DecisionPoint:
    return DecisionPoint(
        config or _config(),
        ["policy"],
        audit if audit is not None else RecordingAudit(),
        sink if sink is not None else RecordingSink(),
        workspace=WORKSPACE,
        evaluate=evaluate or _allow_all,
        self_protect=self_protect or _no_self_protection,
    )


def _allow_all(request: ToolRequest, policies: list, mode: Mode) -> Decision:
    return Decision(Verdict.ALLOW, "allow-all", "allowed")


def _no_self_protection(request: ToolRequest, workspace: Path) -> Decision | None:
    return None


def _request() -> ToolRequest:
    return ToolRequest("coding-agent", "shell.run", {"command": "pytest"}, model="")


@pytest.mark.asyncio
async def test_allow_is_forwarded_and_recorded() -> None:
    audit = RecordingAudit()
    sink = RecordingSink()
    decision = await _dp(audit=audit, sink=sink).decide(_request())
    assert decision.verdict is Verdict.ALLOW
    assert decision.allowed is True
    assert len(audit.entries) == 1
    assert [event.verdict for event in sink.events] == [Verdict.ALLOW]
    assert sink.events[0].tool == "shell.run"
    assert sink.events[0].summary == "pytest"


@pytest.mark.asyncio
async def test_deny_is_recorded_but_not_allowed() -> None:
    def deny(request: ToolRequest, policies: list, mode: Mode) -> Decision:
        return Decision(Verdict.DENY, "shell-allowlist", "not on the allowlist")

    audit = RecordingAudit()
    decision = await _dp(evaluate=deny, audit=audit).decide(_request())
    assert decision.verdict is Verdict.DENY
    assert decision.allowed is False
    assert decision.reason == "not on the allowlist"
    assert len(audit.entries) == 1


@pytest.mark.asyncio
async def test_warn_becomes_deny_until_approvals_exist() -> None:
    def warn(request: ToolRequest, policies: list, mode: Mode) -> Decision:
        return Decision(Verdict.WARN, "pip-install-needs-requirements", "needs a human")

    sink = RecordingSink()
    decision = await _dp(evaluate=warn, sink=sink).decide(_request())
    assert decision.verdict is Verdict.DENY
    assert "needs human approval" in decision.reason
    assert decision.policy == "pip-install-needs-requirements"
    assert sink.events[0].verdict is Verdict.DENY


@pytest.mark.asyncio
async def test_would_deny_is_allowed() -> None:
    def would_deny(request: ToolRequest, policies: list, mode: Mode) -> Decision:
        return Decision(Verdict.WOULD_DENY, "audit", "would have denied")

    decision = await _dp(evaluate=would_deny).decide(_request())
    assert decision.allowed is True


@pytest.mark.asyncio
async def test_unimplemented_policy_engine_fails_closed() -> None:
    def boom(request: ToolRequest, policies: list, mode: Mode) -> Decision:
        raise NotImplementedError("policy engine not written yet")

    audit = RecordingAudit()
    decision = await _dp(evaluate=boom, audit=audit).decide(_request())
    assert decision.verdict is Verdict.DENY
    assert "admit error: NotImplementedError" in decision.reason
    assert decision.allowed is False
    assert len(audit.entries) == 1  # the denial itself is logged


@pytest.mark.asyncio
async def test_arbitrary_evaluation_error_is_a_deny() -> None:
    def boom(request: ToolRequest, policies: list, mode: Mode) -> Decision:
        raise ValueError("bad CEL")

    decision = await _dp(evaluate=boom).decide(_request())
    assert decision.verdict is Verdict.DENY
    assert "ValueError: bad CEL" in decision.reason


@pytest.mark.asyncio
async def test_self_protection_wins_and_skips_policies() -> None:
    called: list[ToolRequest] = []

    def evaluate(request: ToolRequest, policies: list, mode: Mode) -> Decision:
        called.append(request)
        return Decision(Verdict.ALLOW, "allow-all", "allowed")

    def self_protect(request: ToolRequest, workspace: Path) -> Decision | None:
        assert workspace == WORKSPACE
        return Decision(Verdict.DENY, "self-protection", "policy file is read-only")

    decision = await _dp(evaluate=evaluate, self_protect=self_protect).decide(_request())
    assert decision.verdict is Verdict.DENY
    assert decision.policy == "self-protection"
    assert called == []


@pytest.mark.asyncio
async def test_self_protection_error_is_a_deny() -> None:
    def self_protect(request: ToolRequest, workspace: Path) -> Decision | None:
        raise NotImplementedError

    decision = await _dp(self_protect=self_protect).decide(_request())
    assert decision.verdict is Verdict.DENY
    assert "NotImplementedError" in decision.reason


@pytest.mark.asyncio
async def test_audit_failure_denies() -> None:
    sink = RecordingSink()
    decision = await _dp(audit=RecordingAudit(fail=True), sink=sink).decide(_request())
    assert decision.verdict is Verdict.DENY
    assert "audit append failed" in decision.reason
    assert decision.allowed is False
    assert sink.events == []  # nothing is shown that was not logged


@pytest.mark.asyncio
async def test_sink_failure_does_not_deny() -> None:
    decision = await _dp(sink=ExplodingSink()).decide(_request())
    assert decision.verdict is Verdict.ALLOW


@pytest.mark.asyncio
async def test_events_are_numbered() -> None:
    sink = RecordingSink()
    point = _dp(sink=sink)
    await point.decide(_request())
    await point.decide(_request())
    assert [event.seq for event in sink.events] == [1, 2]
    assert all(event.ts.endswith("+00:00") for event in sink.events)


def test_caller_for_token_resolves_bearer() -> None:
    config = _config(callers={"dev-token": "coding-agent", "ci": "ci-bot"})
    assert caller_for_token(config, "Bearer dev-token") == "coding-agent"
    assert caller_for_token(config, "bearer dev-token") == "coding-agent"
    assert caller_for_token(config, "Bearer ci") == "ci-bot"


@pytest.mark.parametrize(
    "header",
    ["", "Bearer", "Bearer ", "Token dev-token", "Bearer wrong", "dev-token", "Basic xyz"],
)
def test_caller_for_token_rejects_anything_else(header: str) -> None:
    config = _config()
    assert caller_for_token(config, header) is None


def test_decision_point_exposes_token_lookup() -> None:
    assert _dp().caller_for_token("Bearer dev-token") == "coding-agent"


def test_null_audit_and_console_sink_are_safe() -> None:
    audit = NullAudit()
    assert audit.append(_request(), Decision(Verdict.ALLOW, None, "")) == {}
    audit.close()
    ConsoleSink().publish(
        Event(
            seq=1,
            ts="2026-11-21T12:00:00+00:00",
            caller="coding-agent",
            tool="shell.run",
            summary="pytest -q",
            verdict=Verdict.DENY,
            policy="shell-allowlist",
            reason="not on the allowlist",
        )
    )


# -- WARN hold through the dashboard approvals ------------------------------


class FakeApprovals:
    def __init__(self, answer: bool | Exception) -> None:
        self.answer = answer
        self.requested: list[tuple[Event, float]] = []

    async def request(self, event: Event, advice: dict | None, timeout_s: float) -> bool:
        self.requested.append((event, timeout_s))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer

    def resolve(self, pending_id: str, approved: bool, by: str) -> None:
        return None


def _warn(request: ToolRequest, policies: list, mode: Mode) -> Decision:
    return Decision(Verdict.WARN, "pip-install", "single-package install")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("answer", "verdict"),
    [(True, Verdict.ALLOW), (False, Verdict.DENY), (RuntimeError("ui crashed"), Verdict.DENY)],
)
async def test_warn_is_held_for_a_human(answer: bool | Exception, verdict: Verdict) -> None:
    approvals = FakeApprovals(answer)
    audit = RecordingAudit()
    dp = DecisionPoint(
        _config(warn_timeout_seconds=7),
        [],
        audit,
        RecordingSink(),
        workspace=WORKSPACE,
        evaluate=_warn,
        self_protect=lambda request, workspace: None,
        approvals=approvals,
    )
    decision = await dp.decide(_request())
    assert decision.verdict is verdict
    assert decision.policy == "pip-install"
    event, timeout = approvals.requested[0]
    assert event.verdict is Verdict.WARN and timeout == 7.0
    # The hold and its outcome are both in the audit log.
    assert [d.verdict for _, d in audit.entries] == [Verdict.WARN, verdict]


@pytest.mark.asyncio
async def test_warn_hold_fails_closed_when_audit_fails() -> None:
    approvals = FakeApprovals(True)
    dp = DecisionPoint(
        _config(),
        [],
        RecordingAudit(fail=True),
        RecordingSink(),
        workspace=WORKSPACE,
        evaluate=_warn,
        self_protect=lambda request, workspace: None,
        approvals=approvals,
    )
    decision = await dp.decide(_request())
    assert decision.verdict is Verdict.DENY
    assert approvals.requested == []  # never shown to a human, never run


def test_summary_redacts_secrets() -> None:
    from admit.decision import summarize_args

    summary = summarize_args({"command": "echo sk_test_FAKE_DO_NOT_USE_0000000000"})
    assert "sk_test" not in summary
    assert "[REDACTED]" in summary
