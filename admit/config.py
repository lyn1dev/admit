"""Admit configuration: mirrors admit.yaml.

Pure dataclasses plus a loader. The YAML shapes below come from ``admit.yaml``
in the repo root (``mode``, ``port``, ``policies``, ``callers`` (token -> caller
id), ``warn.timeout_seconds`` and ``upstreams`` with optional ``env`` per
server). Every error is a ``ValueError`` with the offending key in the message:
``admit serve`` refuses to start rather than run with a half-read config.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from admit.types import Mode

# ${VAR} in an upstream env value is read from Admit's own environment, so
# downstream credentials never have to live in admit.yaml.
_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


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


def _expand(value: str, *, where: str) -> str:
    """Expand ``${VAR}`` from ``os.environ``; a missing variable is an error."""

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        try:
            return os.environ[name]
        except KeyError:
            raise ValueError(f"{where}: environment variable {name!r} is not set") from None

    return _VAR_RE.sub(replace, value)


def _as_str(value: Any, *, where: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{where} must be a string, got {type(value).__name__}")
    return value


def _as_str_list(value: Any, *, where: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        raise ValueError(f"{where} must be a list of strings")
    return [_as_str(item, where=f"{where}[{index}]") for index, item in enumerate(value)]


def _load_upstream(name: str, raw: Any) -> Upstream:
    where = f"upstreams.{name}"
    if not isinstance(raw, dict):
        raise ValueError(f"{where} must be a mapping with a 'command'")
    command = raw.get("command")
    if not isinstance(command, str) or not command.strip():
        raise ValueError(f"{where}: missing 'command' (the program Admit launches over stdio)")
    args = _as_str_list(raw.get("args"), where=f"{where}.args")
    env_raw = raw.get("env") or {}
    if not isinstance(env_raw, dict):
        raise ValueError(f"{where}.env must be a mapping of variable names to strings")
    env = {
        _as_str(key, where=f"{where}.env key"): _expand(
            _as_str(value, where=f"{where}.env.{key}"), where=f"{where}.env.{key}"
        )
        for key, value in env_raw.items()
    }
    cwd = raw.get("cwd")
    if cwd is not None:
        cwd = _as_str(cwd, where=f"{where}.cwd")
    return Upstream(command=command, args=args, env=env, cwd=cwd)


def load_config(path: Path = Path("admit.yaml")) -> AdmitConfig:
    """Load ``admit.yaml`` into an :class:`AdmitConfig`.

    Raises ``ValueError`` for a missing file, an unknown ``mode``, a caller id
    that is not a string, an upstream without ``command`` and an upstream
    ``env`` value whose ``${VAR}`` is unset. Fails closed: a half-read config is
    never returned.
    """
    path = Path(path)
    if not path.is_file():
        raise ValueError(f"config file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:  # pragma: no cover - unreadable file, not a shape error
        raise ValueError(f"cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"{path} is not valid YAML: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must contain a YAML mapping at the top level")

    mode_raw = raw.get("mode", Mode.ENFORCE.value)
    mode_raw = _as_str(mode_raw, where=f"{path}: mode")
    try:
        mode = Mode(mode_raw)
    except ValueError:
        allowed = ", ".join(m.value for m in Mode)
        raise ValueError(
            f"{path}: unknown mode {mode_raw!r} (expected one of: {allowed})"
        ) from None

    port_raw = raw.get("port", 8765)
    if isinstance(port_raw, bool) or not isinstance(port_raw, int):
        raise ValueError(f"{path}: port must be an integer")
    if not 1 <= port_raw <= 65535:
        raise ValueError(f"{path}: port {port_raw} is out of range 1-65535")

    policies = [Path(p) for p in _as_str_list(raw.get("policies"), where=f"{path}: policies")]

    callers_raw = raw.get("callers") or {}
    if not isinstance(callers_raw, dict):
        raise ValueError(f"{path}: callers must be a mapping of token -> caller id")
    callers: dict[str, str] = {}
    for token, caller in callers_raw.items():
        callers[_as_str(token, where=f"{path}: callers key")] = _as_str(
            caller, where=f"{path}: callers.{token}"
        )

    warn_raw = raw.get("warn") or {}
    if not isinstance(warn_raw, dict):
        raise ValueError(f"{path}: warn must be a mapping")
    warn_timeout = warn_raw.get("timeout_seconds", 60)
    if isinstance(warn_timeout, bool) or not isinstance(warn_timeout, int):
        raise ValueError(f"{path}: warn.timeout_seconds must be an integer")

    upstreams_raw = raw.get("upstreams") or {}
    if not isinstance(upstreams_raw, dict):
        raise ValueError(f"{path}: upstreams must be a mapping of name -> server")
    upstreams = {
        _as_str(name, where=f"{path}: upstreams key"): _load_upstream(name, spec)
        for name, spec in upstreams_raw.items()
    }

    return AdmitConfig(
        mode=mode,
        port=port_raw,
        policies=policies or [Path("policies/baseline.yaml")],
        callers=callers,
        upstreams=upstreams,
        warn_timeout_seconds=warn_timeout,
    )
