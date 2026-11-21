"""Hash-chained, Ed25519-signed audit log. Entry fields: admit.types.AUDIT_FIELDS.

The Policy Author agent reads these JSONL files from .admit/audit/.
"""

from __future__ import annotations

from pathlib import Path

from admit.types import Decision, ToolRequest


class AuditLog:
    def __init__(self, directory: Path = Path(".admit/audit")) -> None:
        raise NotImplementedError

    def append(self, request: ToolRequest, decision: Decision) -> dict:
        raise NotImplementedError

    def close(self) -> None:
        """Write the signed session receipt over the last hash."""
        raise NotImplementedError


def verify(log_path: Path) -> tuple[bool, str]:
    """Return (ok, message), e.g. (False, "chain broken at entry 3")."""
    raise NotImplementedError
