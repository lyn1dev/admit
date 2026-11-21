"""Admit configuration: mirrors admit.yaml.

Pure dataclasses plus a loader stub. The YAML shapes below come from
``admit.yaml`` in the repo root (``mode``, ``port``, ``policies``,
``callers`` (token -> caller id), ``warn.timeout_seconds`` and ``upstreams``
with optional ``env`` per server).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from admit.types import Mode


@dataclass
class Upstream:
    """One downstream MCP server launched by Admit over stdio."""

    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None


@dataclass
class AdmitConfig:
    """Resolved configuration for one ``admit serve`` process."""

    mode: Mode = Mode.ENFORCE
    port: int = 8765
    policies: list[Path] = field(default_factory=lambda: [Path("policies/baseline.yaml")])
    callers: dict[str, str] = field(default_factory=dict)
    upstreams: dict[str, Upstream] = field(default_factory=dict)
    warn_timeout_seconds: int = 60


def load_config(path: Path = Path("admit.yaml")) -> AdmitConfig:
    """Load ``admit.yaml`` into an :class:`AdmitConfig`.

    Stub: fail closed on missing file, unknown mode or uncompileable policy
    references once wiring lands.
    """
    raise NotImplementedError
