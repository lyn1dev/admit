"""Audit-mode observations: the Policy Author's local learning data.

The audit log keeps only an ``args_digest`` (no-content-leak rule), which is
not enough to learn a policy from. In **audit mode only**, ``admit serve``
also appends one JSON line per decision to ``.admit/observations/<session>.jsonl``::

    {"ts", "caller", "tool", "model", "args", "verdict"}

String argument values are passed through :func:`admit.redact.redact` and
truncated; file contents being written (``content``/``text``/``data``) are
dropped. ``.admit/`` is gitignored: this never leaves the machine.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from admit.redact import redact
from admit.types import Decision, Mode, ToolRequest

OBSERVATIONS_DIR = Path(".admit/observations")
MAX_VALUE_CHARS = 300
CONTENT_KEYS = frozenset({"content", "contents", "text", "data", "new_string", "old_string"})


def redact_args(value: Any, key: str | None = None) -> Any:
    """Redact every string in ``value`` (recursively); drop file contents."""
    if key in CONTENT_KEYS and isinstance(value, str):
        return f"[omitted: {len(value)} chars]"
    if isinstance(value, str):
        text, _ = redact(value)
        return text[:MAX_VALUE_CHARS]
    if isinstance(value, dict):
        return {str(k): redact_args(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_args(v) for v in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_args(str(value))


class ObservationLog:
    """Append-only JSONL of decisions, for ``admit learn``. A ``DecisionPoint`` observer."""

    def __init__(self, directory: Path = OBSERVATIONS_DIR, mode: Mode = Mode.AUDIT) -> None:
        self.directory = Path(directory)
        self.mode = Mode(mode)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.path = self.directory / f"{stamp}-{os.getpid()}.jsonl"

    @classmethod
    def for_mode(cls, mode: Mode, directory: Path = OBSERVATIONS_DIR) -> ObservationLog | None:
        """An observer for ``serve``: only in audit mode, else ``None``."""
        return cls(directory, mode) if Mode(mode) is Mode.AUDIT else None

    def record(self, request: ToolRequest, decision: Decision) -> None:
        if self.mode is not Mode.AUDIT:
            return
        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "caller": request.caller,
            "tool": request.tool,
            "model": request.model,
            "args": redact_args(dict(request.args or {})),
            "verdict": decision.verdict.value,
        }
        self.directory.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

    __call__ = record
