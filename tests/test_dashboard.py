from __future__ import annotations

import asyncio
import threading
from importlib import resources

import pytest
from starlette.testclient import TestClient

from admit.dashboard import (
    DashboardApprovals,
    DashboardSink,
    create_dashboard_app,
    event_stream,
)
from admit.types import Event, Verdict

KEY = "test-key-123"


def ev(seq: int = 1, verdict: Verdict = Verdict.WARN) -> Event:
    return Event(
        seq, "2026-01-01T00:00:00Z", "coding-agent", "shell.run", "pip install x", verdict, "p", "r"
    )


@pytest.fixture
def setup():
    sink = DashboardSink()
    approvals = DashboardApprovals(sink)
    app = create_dashboard_app(sink, approvals, dashboard_key=KEY)
    client = TestClient(app, base_url="http://127.0.0.1:8765", follow_redirects=False)
    return sink, approvals, client


def login(client: TestClient) -> None:
    r = client.get(f"/?key={KEY}")
    assert r.status_code == 303 and r.headers["location"] == "/"
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "samesite=strict" in sc and "path=/" in sc


def test_cookie_flow(setup):
    _, _, client = setup
    assert client.get("/").status_code == 403
    assert "terminal" in client.get("/").text
    assert client.get("/?key=wrong").status_code == 403
    for path in ("/events", "/verify"):
        assert client.get(path).status_code == 403
    login(client)
    r = client.get("/")
    assert r.status_code == 200 and "<title>Admit</title>" in r.text


def test_approve_deny_need_cookie_and_origin(setup):
    _, approvals, client = setup
    same = {"Origin": "http://127.0.0.1:8765"}
    assert client.post("/approve/x", headers=same).status_code == 403  # no cookie
    login(client)
    assert client.post("/approve/x").status_code == 403  # no origin
    assert client.post("/deny/x", headers={"Origin": "http://evil.test"}).status_code == 403
    ref = {"Referer": "http://127.0.0.1:8765/"}
    assert client.post("/approve/x", headers=ref).status_code == 404
    assert client.post("/deny/unknown", headers=same).status_code == 404


def test_verify_fallback_and_fn():
    sink = DashboardSink()
    ap = DashboardApprovals(sink)

    def nope():
        raise NotImplementedError

    for fn, expected in [
        (None, {"ok": None, "message": "audit verify not available yet"}),
        (nope, {"ok": None, "message": "audit verify not available yet"}),
        (lambda: (True, "fine"), {"ok": True, "message": "fine"}),
        (lambda: (False, "broken at 3"), {"ok": False, "message": "broken at 3"}),
    ]:
        c = TestClient(
            create_dashboard_app(sink, ap, dashboard_key=KEY, verify_fn=fn), follow_redirects=False
        )
        c.cookies.set("admit_dashboard", KEY)
        assert c.get("/verify").json() == expected


async def _wait_pending(sink: DashboardSink) -> dict:
    for _ in range(100):
        for m in list(sink._history):
            if m.get("pending_id"):
                return m
        await asyncio.sleep(0.01)
    raise AssertionError("no pending event")


@pytest.mark.asyncio
@pytest.mark.parametrize("approve", [True, False])
async def test_request_approve_deny(approve):
    sink = DashboardSink()
    ap = DashboardApprovals(sink)
    task = asyncio.create_task(
        ap.request(ev(), {"recommendation": "deny", "risk": "high", "reason": "x"}, 5)
    )
    msg = await _wait_pending(sink)
    assert msg["verdict"] == "WARN" and msg["advice"]["risk"] == "high" and msg["deadline"]
    assert len(msg["pending_id"]) >= 16
    assert ap.resolve(msg["pending_id"], approve, "dashboard") is True
    assert await task is approve
    assert sink._history[-1]["type"] == "update"
    assert sink._history[-1]["status"] == ("approved" if approve else "denied")
    assert ap.resolve(msg["pending_id"], True, "dashboard") is False  # already resolved


@pytest.mark.asyncio
async def test_request_timeout_denies():
    sink = DashboardSink()
    ap = DashboardApprovals(sink)
    assert await ap.request(ev(), None, 0.05) is False
    assert sink._history[-1]["status"] == "timeout"


@pytest.mark.asyncio
async def test_publish_from_other_thread_reaches_subscriber():
    sink = DashboardSink()
    _, queue = sink.subscribe()
    t = threading.Thread(target=sink.publish, args=(ev(7, Verdict.ALLOW),))
    t.start()
    msg = await asyncio.wait_for(queue.get(), 2)
    t.join()
    assert msg["seq"] == 7 and msg["verdict"] == "ALLOW"


@pytest.mark.asyncio
async def test_slow_client_drops_oldest_and_history_replays():
    sink = DashboardSink(history=3, queue_size=2)
    _, queue = sink.subscribe()
    for i in range(5):
        sink.publish(ev(i, Verdict.ALLOW))
    await asyncio.sleep(0.05)
    assert [queue.get_nowait()["seq"] for _ in range(queue.qsize())] == [3, 4]
    gen = event_stream(sink)
    first = await gen.__anext__()
    await gen.aclose()
    assert '"seq": 2' in first  # history keeps the last 3


def test_page_never_uses_inner_html():
    page = resources.files("admit").joinpath("dashboard.html").read_text(encoding="utf-8")
    assert "innerhtml" not in page.lower()
    assert "outerhtml" not in page.lower()
    assert "document.write" not in page
