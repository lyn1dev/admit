"""The one fail-closed decision path every adapter goes through.

Order: caller identity (done by the caller of this module) -> built-in
self-protection -> CEL policies -> audit entry -> live event. Every failure
mode of any component turns into a DENY: an unreachable engine is not a licence
to run the tool. ``policy.evaluate`` and ``selfprotect.check`` are injected so
the gateway works while those modules are still stubs, and picks them up
unchanged once they land.
"""

from __future__ import annotations

import hmac
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console

from admit import policy, selfprotect
from admit.config import AdmitConfig
from admit.types import Decision, Event, EventSink, Mode, ToolRequest, Verdict

_BEARER_RE = re.compile(r"^bearer[ \t]+(\S+)\s*$", re.IGNORECASE)

_VERDICT_STYLE = {
    Verdict.ALLOW: "green",
    Verdict.DENY: "red",
    Verdict.WARN: "yellow",
    Verdict.WOULD_DENY: "blue",
    Verdict.PIN_MISMATCH: "magenta",
}

_SUMMARY_KEYS = ("command", "path", "file_path", "url", "query")


def caller_for_token(config: AdmitConfig, auth_header: str) -> str | None:
    """Resolve ``Authorization: Bearer <token>`` to a caller id.

    The token is compared against every configured token with
    ``hmac.compare_digest`` so a wrong token leaks nothing through timing.
    ``None`` means unauthorized: the caller must be rejected.
    """
    if not auth_header:
        return None
    match = _BEARER_RE.match(auth_header.strip())
    if match is None:
        return None
    token = match.group(1)
    for known, caller in config.callers.items():
        if hmac.compare_digest(known, token):
            return caller
    return None


def summarize_args(args: dict[str, Any]) -> str:
    """A short, human-readable hint for the terminal log (never file contents)."""
    for key in _SUMMARY_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value:
            return value[:120]
    try:
        text = json.dumps(args, ensure_ascii=False, default=str) if args else ""
    except (TypeError, ValueError):  # pragma: no cover - unserializable args
        text = str(sorted(args))
    return text[:120]


class NullAudit:
    """Stand-in for ``admit.audit.AuditLog`` until the real log lands."""

    def append(self, request: ToolRequest, decision: Decision) -> dict:  # noqa: ARG002
        return {}

    def close(self) -> None:
        return None


class ConsoleSink:
    """One colored line per decision on the terminal (the dashboard's twin)."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console(stderr=False)

    def publish(self, event: Event) -> None:
        color = _VERDICT_STYLE.get(event.verdict, "white")
        reason = f" — {event.reason}" if event.reason else ""
        self.console.print(
            f"[{color}]{event.verdict.value:<12}[/] "
            f"[bold]{event.caller}[/] {event.tool} "
            f"[dim]{event.summary}[/]"
            f"{reason}"
        )


class DecisionPoint:
    """Self-protection + CEL + audit + event, in one place for every adapter."""

    def __init__(
        self,
        config: AdmitConfig,
        policies: list,
        audit: object,
        sink: EventSink,
        *,
        workspace: Path,
        evaluate: Callable[[ToolRequest, list, Mode], Decision] = policy.evaluate,
        self_protect: Callable[[ToolRequest, Path], Decision | None] = selfprotect.check,
    ) -> None:
        self.config = config
        self.policies = policies
        self.audit = audit
        self.sink = sink
        self.workspace = Path(workspace)
        self._evaluate = evaluate
        self._self_protect = self_protect
        self._seq = 0

    # -- identity ---------------------------------------------------------

    def caller_for_token(self, auth_header: str) -> str | None:
        return caller_for_token(self.config, auth_header)

    # -- decision ---------------------------------------------------------

    async def decide(self, request: ToolRequest) -> Decision:
        """Decide one call. Never raises: any error is a DENY."""
        try:
            decision = self._decide(request)
        except Exception as exc:  # noqa: BLE001 - fail closed on anything
            decision = _error_decision(exc)
        return self.record(request, decision)

    def _decide(self, request: ToolRequest) -> Decision:
        protected = self._self_protect(request, self.workspace)
        if protected is not None:
            # Built-in rules are deny-only and nothing can override them.
            return Decision(
                Verdict.DENY, protected.policy, protected.reason, protected.hint
            )
        decision = self._evaluate(request, self.policies, self.config.mode)
        if decision.verdict is Verdict.WARN:
            # No approval UI yet: a held call is a deny, never an allow.
            return Decision(
                Verdict.DENY,
                decision.policy,
                f"{decision.reason} (needs human approval)",
                decision.hint,
            )
        return decision

    # -- audit + event ----------------------------------------------------

    def record(self, request: ToolRequest, decision: Decision) -> Decision:
        """Append to the audit log, then publish the event.

        An audit failure is a DENY (no unlogged call ever runs); an event-sink
        failure only costs a log line.
        """
        try:
            self.audit.append(request, decision)
        except Exception as exc:  # noqa: BLE001 - fail closed on anything
            return Decision(
                Verdict.DENY,
                decision.policy,
                f"admit error: audit append failed: {type(exc).__name__}: {exc}",
            )
        self._publish(request, decision)
        return decision

    def _publish(self, request: ToolRequest, decision: Decision) -> None:
        self._seq += 1
        event = Event(
            seq=self._seq,
            ts=datetime.now(UTC).isoformat(),
            caller=request.caller,
            tool=request.tool,
            summary=summarize_args(request.args),
            verdict=decision.verdict,
            policy=decision.policy,
            reason=decision.reason,
        )
        try:
            self.sink.publish(event)
        except Exception:  # noqa: BLE001 - a display bug must not deny the call
            return


def _error_decision(exc: BaseException) -> Decision:
    return Decision(Verdict.DENY, None, f"admit error: {type(exc).__name__}: {exc}")


__all__ = [
    "ConsoleSink",
    "DecisionPoint",
    "NullAudit",
    "caller_for_token",
    "summarize_args",
]
