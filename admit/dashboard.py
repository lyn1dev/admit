"""Live dashboard routes served next to /mcp: page, SSE feed, approve/deny, verify.

Served by ``admit serve`` at ``http://127.0.0.1:8765/``. Cards are plain
English; the rich terminal log stays as a fallback.

Security: the agent runs on the same machine and could ``curl`` these
endpoints, so everything except the landing page needs a random
``dashboard_key`` (printed only in the Admit terminal) delivered as an
HttpOnly cookie. Approve/Deny additionally require a same-origin
``Origin``/``Referer`` header. Only summary fields go on the page, never file
contents or tool output.

Dev runner: ``uv run python -m admit.dashboard --fake [--port 8766]``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hmac
import json
import secrets
import threading
import time
from collections import deque
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from importlib import resources
from typing import Any
from urllib.parse import urlsplit

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from starlette.routing import Route

from admit.types import Approvals, Event, EventSink, Verdict

COOKIE_NAME = "admit_dashboard"
HISTORY_SIZE = 200
QUEUE_SIZE = 256
HEARTBEAT_S = 15.0


def event_to_message(event: Event, **extra: Any) -> dict[str, Any]:
    """Whitelisted, JSON-safe view of an Event: only fields meant for the page."""
    msg: dict[str, Any] = {
        "type": "event",
        "seq": event.seq,
        "ts": event.ts,
        "caller": event.caller,
        "tool": event.tool,
        "summary": event.summary,
        "verdict": Verdict(event.verdict).value,
        "policy": event.policy,
        "reason": event.reason,
        "pending_id": event.pending_id,
        "model": getattr(event, "model", "") or "",
        "advice": None,
        "deadline": None,
    }
    msg.update(extra)
    return msg


class DashboardSink:
    """EventSink: broadcasts decisions to connected SSE clients.

    Thread-safe: ``publish`` may be called from any thread or event loop and
    never blocks. Each client gets a bounded queue; the oldest message is
    dropped for slow clients.
    """

    def __init__(self, history: int = HISTORY_SIZE, queue_size: int = QUEUE_SIZE) -> None:
        self._history: deque[dict[str, Any]] = deque(maxlen=history)
        self._subs: list[tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]] = []
        self._queue_size = queue_size
        self._lock = threading.Lock()

    def publish(self, event: Event) -> None:
        """Fan out one decision event to every open /events stream."""
        self.publish_message(event_to_message(event))

    def publish_message(self, msg: dict[str, Any]) -> None:
        with self._lock:
            self._history.append(msg)
            subs = list(self._subs)
        for loop, queue in subs:
            try:
                loop.call_soon_threadsafe(self._offer, queue, msg)
            except RuntimeError:  # that client's loop is closed
                self._drop(queue)

    @staticmethod
    def _offer(queue: asyncio.Queue[dict[str, Any]], msg: dict[str, Any]) -> None:
        if queue.full():
            try:
                queue.get_nowait()  # drop oldest
            except asyncio.QueueEmpty:
                pass
        queue.put_nowait(msg)

    def _drop(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        with self._lock:
            self._subs = [s for s in self._subs if s[1] is not queue]

    def subscribe(self) -> tuple[list[dict[str, Any]], asyncio.Queue[dict[str, Any]]]:
        """Register the calling loop; returns (history snapshot, live queue)."""
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self._queue_size)
        loop = asyncio.get_running_loop()
        with self._lock:
            snapshot = list(self._history)
            self._subs.append((loop, queue))
        return snapshot, queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._drop(queue)


class DashboardApprovals:
    """Approvals: backs the /approve and /deny buttons with pending WARN calls."""

    def __init__(self, sink: DashboardSink) -> None:
        self._sink = sink
        self._pending: dict[str, tuple[asyncio.AbstractEventLoop, asyncio.Future[tuple[bool, str]]]]
        self._pending = {}

    async def request(self, event: Event, advice: dict[str, Any] | None, timeout_s: float) -> bool:
        """Block until a human decides; timeout returns False (deny)."""
        pending_id = event.pending_id or secrets.token_urlsafe(16)
        held = dataclasses.replace(event, verdict=Verdict.WARN, pending_id=pending_id)
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[tuple[bool, str]] = loop.create_future()
        self._pending[pending_id] = (loop, fut)
        advice_view = (
            {k: advice.get(k) for k in ("recommendation", "risk", "reason")} if advice else None
        )
        self._sink.publish_message(
            event_to_message(held, advice=advice_view, deadline=time.time() + timeout_s)
        )
        approved, status, by = False, "timeout", "timeout"
        try:
            approved, by = await asyncio.wait_for(fut, timeout_s)
            status = "approved" if approved else "denied"
        except TimeoutError:
            pass
        finally:
            self._pending.pop(pending_id, None)
            self._sink.publish_message(
                {"type": "update", "pending_id": pending_id, "status": status, "by": by}
            )
        return approved

    def resolve(self, pending_id: str, approved: bool, by: str) -> bool:
        """Record a human Approve/Deny for ``pending_id``. False if unknown/resolved."""
        entry = self._pending.pop(pending_id, None)
        if entry is None:
            return False
        loop, fut = entry

        def _set() -> None:
            if not fut.done():
                fut.set_result((approved, by))

        loop.call_soon_threadsafe(_set)
        return True


# --------------------------------------------------------------------------- HTTP


def _authed(request: Request, key: str) -> bool:
    cookie = request.cookies.get(COOKIE_NAME, "")
    return hmac.compare_digest(cookie.encode(), key.encode())


def _same_origin(request: Request) -> bool:
    ref = request.headers.get("origin") or request.headers.get("referer")
    host = request.headers.get("host")
    if not ref or not host:
        return False
    return urlsplit(ref).netloc == host


def _sse(msg: dict[str, Any]) -> str:
    return f"data: {json.dumps(msg)}\n\n"


async def event_stream(sink: DashboardSink) -> AsyncIterator[str]:
    """History first, then live messages; a comment heartbeat when idle."""
    snapshot, queue = sink.subscribe()
    try:
        for msg in snapshot:
            yield _sse(msg)
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), HEARTBEAT_S)
            except TimeoutError:
                yield ": heartbeat\n\n"
                continue
            yield _sse(msg)
    finally:
        sink.unsubscribe(queue)


_NEED_LINK = (
    "<!doctype html><meta charset=utf-8><title>Admit</title>"
    "<body style='font:28px system-ui;max-width:30em;margin:15vh auto;padding:1em'>"
    "<h1>Admit</h1><p>Open the link printed in the Admit terminal.</p></body>"
)


def routes(
    sink: EventSink,
    approvals: Approvals,
    *,
    dashboard_key: str,
    verify_fn: Callable[[], tuple[bool, str]] | None = None,
) -> list[Route]:
    """Starlette routes:

    - GET / -- single HTML dashboard page (no build step); ``?key=`` sets the cookie
    - GET /events -- server-sent events, history then live
    - POST /approve/{pending_id} / POST /deny/{pending_id} -- resolve a held WARN call
    - GET /verify -- current log verification status for the badge
    """
    page = resources.files("admit").joinpath("dashboard.html").read_text(encoding="utf-8")

    async def index(request: Request) -> Response:
        supplied = request.query_params.get("key")
        if supplied is not None:
            if not hmac.compare_digest(supplied.encode(), dashboard_key.encode()):
                return HTMLResponse(_NEED_LINK, status_code=403)
            resp = RedirectResponse("/", status_code=303)
            resp.set_cookie(COOKIE_NAME, dashboard_key, httponly=True, samesite="strict", path="/")
            return resp
        if not _authed(request, dashboard_key):
            return HTMLResponse(_NEED_LINK, status_code=403)
        return HTMLResponse(page, headers={"Cache-Control": "no-store"})

    async def events(request: Request) -> Response:
        if not _authed(request, dashboard_key):
            return Response("forbidden", status_code=403)
        if not isinstance(sink, DashboardSink):
            return Response("sink does not stream", status_code=500)
        return StreamingResponse(
            event_stream(sink),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    def _resolver(approved: bool) -> Callable[[Request], Any]:
        async def handler(request: Request) -> Response:
            if not _authed(request, dashboard_key) or not _same_origin(request):
                return JSONResponse({"error": "forbidden"}, status_code=403)
            pending_id = request.path_params["pending_id"]
            if approvals.resolve(pending_id, approved, "dashboard") is False:
                return JSONResponse({"error": "unknown or already resolved"}, status_code=404)
            return JSONResponse({"ok": True})

        return handler

    async def verify(request: Request) -> Response:
        if not _authed(request, dashboard_key):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        unavailable = {"ok": None, "message": "audit verify not available yet"}
        if verify_fn is None:
            return JSONResponse(unavailable)
        try:
            ok, message = await asyncio.to_thread(verify_fn)
        except NotImplementedError:
            return JSONResponse(unavailable)
        return JSONResponse({"ok": bool(ok), "message": str(message)})

    return [
        Route("/", index),
        Route("/events", events),
        Route("/approve/{pending_id}", _resolver(True), methods=["POST"]),
        Route("/deny/{pending_id}", _resolver(False), methods=["POST"]),
        Route("/verify", verify),
    ]


def create_dashboard_app(
    sink: DashboardSink,
    approvals: Approvals,
    *,
    dashboard_key: str,
    verify_fn: Callable[[], tuple[bool, str]] | None = None,
    **starlette_kwargs: Any,
) -> Starlette:
    return Starlette(
        routes=routes(sink, approvals, dashboard_key=dashboard_key, verify_fn=verify_fn),
        **starlette_kwargs,
    )


# --------------------------------------------------------------------------- dev runner


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


async def _fake_source(sink: DashboardSink, approvals: DashboardApprovals) -> None:
    """Emit a realistic mix of decisions every few seconds (dev/demo only)."""
    seq = 0

    def mk(tool: str, summary: str, verdict: Verdict, policy: str | None, reason: str) -> Event:
        nonlocal seq
        seq += 1
        return Event(seq, _now(), "coding-agent", tool, summary, verdict, policy, reason)

    advice = {
        "recommendation": "deny",
        "risk": "high",
        "reason": "Installing an unpinned package can run arbitrary install scripts.",
    }
    script: list[Callable[[], Event]] = [
        lambda: mk("shell.run", "pytest -q", Verdict.ALLOW, "shell-allowlist", "allowed command"),
        lambda: mk(
            "shell.run",
            "python scripts/bootstrap.py",
            Verdict.DENY,
            "shell-allowlist",
            "Command is not on the allowlist.",
        ),
        lambda: mk(
            "shell.run", "pip install requests", Verdict.WARN, "package-install", "Needs approval."
        ),
        lambda: mk(
            "shell.run",
            "type .env",
            Verdict.DENY,
            "self-protection",
            "Reading secrets files is not allowed.",
        ),
        lambda: mk(
            "fs.read_text_file",
            "src/app.py",
            Verdict.WOULD_DENY,
            "fs-scope",
            "Outside the project (audit mode).",
        ),
    ]
    tasks: set[asyncio.Task[Any]] = set()
    while True:
        for make in script:
            await asyncio.sleep(3)
            ev = make()
            if ev.verdict is Verdict.WARN:
                task = asyncio.create_task(approvals.request(ev, advice, 60.0))
                tasks.add(task)
                task.add_done_callback(tasks.discard)
            else:
                sink.publish(ev)


def main(argv: list[str] | None = None) -> None:
    import argparse
    from contextlib import asynccontextmanager

    import uvicorn

    parser = argparse.ArgumentParser(description="Admit dashboard dev runner")
    parser.add_argument("--fake", action="store_true", required=True, help="emit fake events")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args(argv)

    sink = DashboardSink()
    approvals = DashboardApprovals(sink)
    key = secrets.token_urlsafe(24)

    @asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        task = asyncio.create_task(_fake_source(sink, approvals))
        try:
            yield
        finally:
            task.cancel()

    app = create_dashboard_app(sink, approvals, dashboard_key=key, lifespan=lifespan)
    print(f"Admit dashboard (fake events): http://127.0.0.1:{args.port}/?key={key}", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
