"""Shared contracts between the proxy, policy engine, audit log, dashboard and agents.

Change these only by agreement: the proxy, policy engine, audit log and the
ADK agents all depend on them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol


class Mode(StrEnum):
    ENFORCE = "enforce"
    AUDIT = "audit"  # allow everything, log what would have happened (learn mode)


class Verdict(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    WARN = "WARN"  # held for human approval
    WOULD_DENY = "WOULD_DENY"  # allowed, but a policy (or audit mode) would have denied
    PIN_MISMATCH = "PIN_MISMATCH"


@dataclass(frozen=True)
class ToolRequest:
    """One tool call as seen by the policy engine. CEL sees it as `request`."""

    caller: str  # e.g. "coding-agent", resolved from the bearer token
    tool: str  # namespaced, e.g. "shell.run", "fs.read_text_file"
    args: dict[str, Any] = field(default_factory=dict)
    model: str = ""  # "provider/id" if known (antigravity/<modelName>, Pi), else ""

    def to_cel(self) -> dict[str, Any]:
        return {"caller": self.caller, "tool": self.tool, "args": self.args, "model": self.model}


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    policy: str | None  # name of the deciding policy; None for default-deny
    reason: str
    hint: str | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict in (Verdict.ALLOW, Verdict.WOULD_DENY)

    def to_agent_error(self) -> dict[str, Any]:
        """Explained denial returned to the agent as a structured tool error."""
        return {
            "admit": {
                "decision": self.verdict.value,
                "policy": self.policy,
                "reason": self.reason,
                "hint": self.hint
                or "Continue without this step and tell the user it was blocked.",
            }
        }


# One line of .admit/audit/<session>.jsonl. Args are stored only as a digest so
# secrets never land in the log (no-content-leak rule).
AUDIT_FIELDS = (
    "seq",
    "ts",
    "caller",
    "tool",
    "args_digest",
    "decision",
    "policy",
    "reason",
    "prev_hash",
    "hash",
)


def normalize_tool(name: str) -> str:
    """FastMCP mounts tools as `fs_read_text_file`; policies use `fs.read_text_file`."""
    prefix, sep, rest = name.partition("_")
    return f"{prefix}.{rest}" if sep and "." not in prefix else name


@dataclass(frozen=True)
class Event:
    """One decision, published to the terminal log and the dashboard.

    `summary` is a short, truncated description of the arguments for humans
    (e.g. the command line). It is never written to the audit log, which keeps
    only `args_digest`, and it never contains file contents or tool output.
    """

    seq: int
    ts: str  # ISO 8601 UTC
    caller: str
    tool: str
    summary: str
    verdict: Verdict
    policy: str | None
    reason: str
    pending_id: str | None = None  # set while a WARN call waits for a human


class EventSink(Protocol):
    """Anything that shows decisions live: rich console, dashboard feed."""

    def publish(self, event: Event) -> None: ...


class Approvals(Protocol):
    """Human-in-the-loop for WARN calls. The dashboard buttons call `resolve`."""

    async def request(self, event: Event, advice: dict | None, timeout_s: float) -> bool:
        """Block until a human decides. Timeout returns False (deny)."""
        ...

    def resolve(self, pending_id: str, approved: bool, by: str) -> None: ...
