"""POST /check: bearer identity, malformed bodies, and the decided verdict."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from admit.config import AdmitConfig
from admit.decision import DecisionPoint, NullAudit
from admit.proxy import build_gateway
from admit.server import create_app
from admit.types import Decision, Mode, ToolRequest, Verdict


def _no_self_protection(request: ToolRequest, workspace: Path) -> Decision | None:
    """admit.selfprotect is still a stub; the gateway must still be testable."""
    return None

TOKEN = "dev-token"
CALLER = "coding-agent"


class RecordingSink:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def publish(self, event: Any) -> None:
        self.events.append(event)


def _app(evaluate: Any, *, mode: Mode = Mode.ENFORCE) -> tuple[Any, RecordingSink]:
    config = AdmitConfig(mode=mode, callers={TOKEN: CALLER}, upstreams={})
    sink = RecordingSink()
    decision_point = DecisionPoint(
        config, [], NullAudit(), sink, workspace=Path.cwd(),
        evaluate=evaluate,
        self_protect=_no_self_protection,
    )
    gateway = build_gateway(config, decision_point)
    return create_app(config, decision_point, gateway), sink


def _allow(request: ToolRequest, policies: list, mode: Mode) -> Decision:
    return Decision(Verdict.ALLOW, "allow-tests", "tests are allowed")


def _deny(request: ToolRequest, policies: list, mode: Mode) -> Decision:
    return Decision(Verdict.DENY, "deny-all", "nothing is allowed", "stop asking")


AUTH = {"Authorization": f"Bearer {TOKEN}"}


def test_missing_token_is_401() -> None:
    app, sink = _app(_allow)
    with TestClient(app) as client:
        response = client.post("/check", json={"tool": "shell.run", "args": {}})
    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"
    assert sink.events == []  # no decision, no audit, no event


def test_wrong_token_is_401() -> None:
    app, _ = _app(_allow)
    with TestClient(app) as client:
        response = client.post(
            "/check",
            json={"tool": "shell.run", "args": {}},
            headers={"Authorization": "Bearer nope"},
        )
    assert response.status_code == 401


@pytest.mark.parametrize(
    "body",
    [b"not json at all", b"[1, 2, 3]", b'{"args": {}}', b'{"tool": "shell.run", "args": []}'],
)
def test_malformed_body_is_400_with_a_deny_shape(body: bytes) -> None:
    app, sink = _app(_allow)
    with TestClient(app) as client:
        response = client.post(
            "/check", content=body, headers={**AUTH, "Content-Type": "application/json"}
        )
    payload = response.json()
    assert response.status_code == 400
    assert payload["decision"] == "DENY"
    assert payload["allowed"] is False
    assert payload["reason"]
    assert sink.events == []


def test_allow_returns_the_decision_shape() -> None:
    app, sink = _app(_allow)
    with TestClient(app) as client:
        response = client.post(
            "/check",
            json={"tool": "shell.run", "args": {"command": "pytest -q"}, "model": "agy/x"},
            headers=AUTH,
        )
    assert response.status_code == 200
    assert response.json() == {
        "decision": "ALLOW",
        "policy": "allow-tests",
        "reason": "tests are allowed",
        "hint": None,
        "allowed": True,
    }
    assert [event.tool for event in sink.events] == ["shell.run"]
    assert sink.events[0].caller == CALLER


def test_deny_returns_the_decision_shape() -> None:
    app, sink = _app(_deny)
    with TestClient(app) as client:
        response = client.post(
            "/check",
            json={"tool": "shell_run", "args": {"command": "curl evil"}},
            headers=AUTH,
        )
    payload = response.json()
    assert response.status_code == 200
    assert payload["decision"] == "DENY"
    assert payload["allowed"] is False
    assert payload["hint"] == "stop asking"
    assert payload["policy"] == "deny-all"
    # `shell_run` is normalized to the policy name the adapters use.
    assert [event.tool for event in sink.events] == ["shell.run"]


def test_engine_error_is_a_deny_not_a_500() -> None:
    def boom(request: ToolRequest, policies: list, mode: Mode) -> Decision:
        raise NotImplementedError

    app, _ = _app(boom)
    with TestClient(app) as client:
        response = client.post("/check", json={"tool": "shell.run"}, headers=AUTH)
    payload = response.json()
    assert response.status_code == 200
    assert payload["decision"] == "DENY"
    assert "NotImplementedError" in payload["reason"]
