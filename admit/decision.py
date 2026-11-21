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
from rich.markup import escape

from admit import policy, selfprotect
from admit.config import AdmitConfig
from admit.redact import redact
from admit.types import Approvals, Decision, Event, EventSink, Mode, ToolRequest, Verdict

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
    """A short, human-readable hint for the terminal and dashboard (never file contents).

    Secret patterns are redacted: the summary is shown on screen, often on stage.
    """
    text = ""
    for key in _SUMMARY_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value:
            text = value
            break
    else:
        try:
            text = json.dumps(args, ensure_ascii=False, default=str) if args else ""
        except (TypeError, ValueError):  # pragma: no cover - unserializable args
            text = str(sorted(args))
    try:
        text, _ = redact(text)
    except Exception:  # noqa: BLE001 - never show an unredacted value
        return "[summary unavailable]"
    return text[:120]


class FanoutSink:
    """Publish every event to several sinks (terminal + dashboard). One failing sink
    never stops the others."""

    def __init__(self, *sinks: EventSink) -> None:
        self.sinks = sinks

    def publish(self, event: Event) -> None:
        for sink in self.sinks:
            try:
                sink.publish(event)
            except Exception:  # noqa: BLE001 - display only
                continue


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
        model = getattr(event, "model", "") or ""
        model = f"[magenta]{escape(f'[{model}]')}[/] " if model else ""
        self.console.print(
            f"[{color}]{event.verdict.value:<12}[/] "
            f"[bold]{event.caller}[/] {model}{event.tool} "
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
        approvals: Approvals | None = None,
        observer: Callable[[ToolRequest, Decision], None] | None = None,
    ) -> None:
        self.config = config
        self.policies = policies
        self.audit = audit
        self.sink = sink
        self.workspace = Path(workspace)
        self._evaluate = evaluate
        self._self_protect = self_protect
        self.approvals = approvals
        # Audit-mode learning data (admit.observations); never affects the decision.
        self.observer = observer
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
        if decision.verdict is Verdict.WARN:
            return await self._hold(request, decision)
        return self.record(request, decision)

    async def _hold(self, request: ToolRequest, warn: Decision) -> Decision:
        """WARN: log the hold, wait for a human on the dashboard, log the outcome.

        Timeout, a missing approval UI or any error is a DENY.
        """
        try:
            self.audit.append(request, warn)
        except Exception as exc:  # noqa: BLE001 - fail closed on anything
            return Decision(
                Verdict.DENY,
                warn.policy,
                f"admit error: audit append failed: {type(exc).__name__}: {exc}",
            )
        approved = False
        try:
            if self.approvals is not None:
                approved = await self.approvals.request(
                    self._event(request, warn),
                    None,
                    float(self.config.warn_timeout_seconds),
                )
        except Exception:  # noqa: BLE001 - fail closed on anything
            approved = False
        if approved:
            final = Decision(
                Verdict.ALLOW, warn.policy, f"{warn.reason} (approved on the dashboard)", warn.hint
            )
        else:
            final = Decision(
                Verdict.DENY,
                warn.policy,
                f"{warn.reason} (needs human approval: denied or timed out)",
                warn.hint,
            )
        return self.record(request, final)

    def _decide(self, request: ToolRequest) -> Decision:
        protected = self._self_protect(request, self.workspace)
        if protected is not None:
            # Built-in rules are deny-only and nothing can override them.
            return Decision(
                Verdict.DENY, protected.policy, protected.reason, protected.hint
            )
        decision = self._evaluate(request, self.policies, self.config.mode)
        if not isinstance(decision, Decision):
            raise TypeError(f"policy engine returned {type(decision).__name__}, not Decision")
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
        if self.observer is not None:
            try:
                self.observer(request, decision)
            except Exception:  # noqa: BLE001 - learning data must never deny a call
                pass
        self._publish(request, decision)
        return decision

    def _publish(self, request: ToolRequest, decision: Decision) -> None:
        try:
            self.sink.publish(self._event(request, decision))
        except Exception:  # noqa: BLE001 - a display bug must not deny the call
            return

    def _event(self, request: ToolRequest, decision: Decision) -> Event:
        self._seq += 1
        return Event(
            seq=self._seq,
            ts=datetime.now(UTC).isoformat(),
            caller=request.caller,
            tool=request.tool,
            summary=summarize_args(request.args),
            verdict=decision.verdict,
            policy=decision.policy,
            reason=decision.reason,
            model=request.model,
        )


def _error_decision(exc: BaseException) -> Decision:
    return Decision(Verdict.DENY, None, f"admit error: {type(exc).__name__}: {exc}")


__all__ = [
    "ConsoleSink",
    "DecisionPoint",
    "FanoutSink",
    "NullAudit",
    "caller_for_token",
    "summarize_args",
]
