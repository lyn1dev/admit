"""Live dashboard routes served next to /mcp: page, SSE feed, approve/deny, verify, check.

Served by ``admit serve`` at ``http://127.0.0.1:8765/``. Cards are plain
English; the rich terminal log stays as a fallback.
"""

from __future__ import annotations

from typing import Any

from starlette.routing import Route

from admit.types import Approvals, Event, EventSink


class DashboardSink:
    """EventSink: broadcasts decisions to connected SSE clients."""

    def publish(self, event: Event) -> None:
        """Fan out one decision event to every open /events stream."""
        raise NotImplementedError


class DashboardApprovals:
    """Approvals: backs the /approve and /deny buttons with pending WARN calls."""

    async def request(self, event: Event, advice: dict[str, Any] | None, timeout_s: float) -> bool:
        """Block until a human decides; timeout returns False (deny)."""
        raise NotImplementedError

    def resolve(self, pending_id: str, approved: bool, by: str) -> None:
        """Record a human Approve/Deny for ``pending_id``."""
        raise NotImplementedError


def routes(sink: EventSink, approvals: Approvals) -> list[Route]:
    """Starlette routes:

    - GET / -- single HTML dashboard page (no build step)
    - GET /events -- server-sent events, one Event per decision
    - POST /approve/{pending_id} / POST /deny/{pending_id} -- resolve a held WARN call
    - GET /verify -- current log verification status for the badge
    - POST /check -- decision for a hook call (bearer token required)
    """
    raise NotImplementedError
