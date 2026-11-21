"""Static scan of an agent MCP / hook config for risky settings (plan section 8).

No network and no model calls: one :class:`Finding` per problem, then
:func:`score` out of 100 (100 minus penalties, floored at 0). Secrets found in a
config are reported by key name only, never by value.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SEVERITY_PENALTY = {"high": 30, "med": 10, "low": 3}

# Project-level config files per harness (relative to the project root).
HARNESS_FILES: dict[str, str] = {
    "antigravity": ".agents/hooks.json",
    "gemini": ".gemini/settings.json",
    "claude": ".claude/settings.json",
}
_MCP_ONLY_FILES = (".mcp.json", ".agents/mcp_config.json")

_ADMIT_HOOK_RE = re.compile(r"admit(?:\.cli)?[ .]hook|admit\.hook", re.IGNORECASE)
_SHELL_RE = re.compile(r"shell|exec|terminal|bash|powershell|pwsh", re.IGNORECASE)
_SECRET_RE = re.compile(
    r"(?:ghp_|gho_|ghs_|github_pat_|sk-|sk_|AKIA|ASIA|xox[abposr]-|AIza)[A-Za-z0-9_\-]{8,}"
)
_DRIVE_ROOT_RE = re.compile(r"^[A-Za-z]:[\\/]?$")
_HOME_ALIASES = {"~", "~/", "~\\", "$HOME", "${HOME}", "%USERPROFILE%", "/"}


@dataclass(frozen=True)
class Finding:
    """One posture finding."""

    severity: str  # "high" | "med" | "low"
    check: str
    detail: str


def score(findings: list[Finding]) -> int:
    """100 minus per-severity penalties, floored at 0."""
    penalty = sum(SEVERITY_PENALTY.get(finding.severity, 0) for finding in findings)
    return max(0, 100 - penalty)


# --------------------------------------------------------------------------- helpers


def is_admit_hook_command(command: str) -> bool:
    return bool(_ADMIT_HOOK_RE.search(command))


def hook_entries(data: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    """Every pre-tool hook entry (``{"type", "command", "timeout", ...}``) in a config."""
    groups: list[Any] = []
    if kind == "antigravity":
        for block in data.values():
            if isinstance(block, dict) and block.get("enabled", True) is not False:
                groups.extend(block.get("PreToolUse") or [])
    else:
        hooks = data.get("hooks")
        if isinstance(hooks, dict):
            for event in ("BeforeTool", "PreToolUse"):
                groups.extend(hooks.get(event) or [])
    entries: list[dict[str, Any]] = []
    for group in groups:
        if isinstance(group, dict):
            entries.extend(h for h in group.get("hooks") or [] if isinstance(h, dict))
    return entries


def admit_hooks(data: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [
        h for h in hook_entries(data, kind) if is_admit_hook_command(str(h.get("command", "")))
    ]


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def looks_like_secret(value: str) -> bool:
    if "${" in value or "$(" in value:
        return False  # reference to the environment, not a literal
    if value.lower().startswith("bearer "):
        value = value[7:].strip()
    if _SECRET_RE.search(value):
        return True
    return (
        len(value) >= 32
        and " " not in value
        and "/" not in value
        and "\\" not in value
        and _entropy(value) >= 4.0
    )


def _is_broad_root(arg: str) -> bool:
    arg = arg.strip().strip('"')
    if arg in _HOME_ALIASES or _DRIVE_ROOT_RE.match(arg):
        return True
    try:
        home = Path.home().resolve()
        return Path(arg).expanduser().resolve() == home and Path(arg).is_absolute()
    except (OSError, RuntimeError, ValueError):
        return False


def _is_admit_server(name: str, spec: dict[str, Any]) -> bool:
    url = str(spec.get("url") or spec.get("httpUrl") or "")
    return name.lower() == "admit" or ":8765/mcp" in url


def _project_root(config_path: Path) -> Path:
    parent = config_path.parent
    if parent.name in {".gemini", ".agents", ".claude"}:
        return parent.parent
    return parent


def detect_kind(config_path: Path) -> str:
    """``antigravity`` | ``gemini`` | ``claude`` | ``mcp`` | ``settings`` (unknown harness)."""
    parent, name = config_path.parent.name, config_path.name
    if parent == ".agents" and name == "hooks.json":
        return "antigravity"
    if parent == ".gemini":
        return "gemini"
    if parent == ".claude":
        return "claude"
    if name in {".mcp.json", "mcp_config.json"}:
        return "mcp"
    return "settings"


# --------------------------------------------------------------------------- checks


def _builtins_disabled(data: dict[str, Any], kind: str) -> bool:
    if kind == "antigravity":
        return False  # agy has no setting that disables built-in tools
    tools = data.get("tools")
    if isinstance(tools, dict) and tools.get("core") == []:
        return True
    perms = data.get("permissions")
    deny = perms.get("deny") if isinstance(perms, dict) else None
    if isinstance(deny, list):
        return {"Bash", "Read", "Edit", "Write"} <= {str(d).split("(")[0] for d in deny}
    return False


def _server_findings(data: dict[str, Any], project: Path | None) -> list[Finding]:
    findings: list[Finding] = []
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return findings
    admit_seen = False
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        if _is_admit_server(name, spec):
            admit_seen = True
            continue
        findings.append(
            Finding("high", "mcp-bypass", f"MCP server '{name}' is reachable without Admit")
        )
        args = [str(a) for a in spec.get("args") or []]
        haystack = " ".join([name, str(spec.get("command", "")), *args])
        if _SHELL_RE.search(haystack):
            findings.append(
                Finding("high", "shell-server", f"MCP server '{name}' can run shell commands")
            )
        for arg in args:
            if not arg.startswith("-") and _is_broad_root(arg):
                findings.append(
                    Finding("high", "broad-fs-root", f"MCP server '{name}' exposes '{arg}'")
                )
        for section in ("env", "headers"):
            values = spec.get(section)
            if not isinstance(values, dict):
                continue
            for key, value in values.items():
                if isinstance(value, str) and looks_like_secret(value):
                    findings.append(
                        Finding(
                            "high",
                            "plaintext-secret",
                            f"MCP server '{name}' has a plaintext secret in {section}.{key}",
                        )
                    )
    if admit_seen and project is not None and not (project / ".admit" / "pins.json").is_file():
        findings.append(
            Finding("low", "tools-not-pinned", "Admit configured but .admit/pins.json is missing")
        )
    return findings


def scan_data(data: dict[str, Any], kind: str, project: Path | None = None) -> list[Finding]:
    """Scan one parsed config of the given ``kind`` (see :func:`detect_kind`)."""
    findings = _server_findings(data, project)

    security = data.get("security")
    folder_trust = security.get("folderTrust") if isinstance(security, dict) else None
    if isinstance(folder_trust, dict) and folder_trust.get("enabled") is False:
        findings.append(Finding("low", "folder-trust-off", "Folder trust is disabled"))

    if kind == "mcp":
        return findings  # MCP-only file: built-ins and hooks live elsewhere

    hooks = admit_hooks(data, kind)
    builtins_off = _builtins_disabled(data, kind)
    if not hooks:
        if builtins_off:
            findings.append(Finding("med", "hook-missing", "No Admit hook installed"))
        else:
            findings.append(
                Finding(
                    "high",
                    "builtins-unchecked",
                    "Built-in tools are on and no Admit hook checks them",
                )
            )
    for hook in hooks:
        if "timeout" not in hook:
            findings.append(
                Finding("med", "hook-no-timeout", "Admit hook has no explicit timeout")
            )
    return findings


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8-sig") or "{}")
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return data


def scan_harness(
    project: Path, harness: str, data: dict[str, Any] | None = None
) -> list[Finding]:
    """Posture of one harness in ``project``; a missing config means "nothing checks it".

    ``data`` overrides the file on disk (used by ``admit init --dry-run``).
    """
    rel = HARNESS_FILES.get(harness)
    if rel is None:
        return []
    path = project / rel
    if data is None:
        if not path.is_file():
            return [
                Finding(
                    "high",
                    "builtins-unchecked",
                    f"{harness}: no {rel}, built-in tools run with no Admit hook",
                )
            ]
        data = _load_json(path)
    return [
        Finding(f.severity, f.check, f"{harness}: {f.detail}")
        for f in scan_data(data, harness, project)
    ]


def scan(config_path: Path) -> list[Finding]:
    """Scan an agent config file, or every known config in a project directory."""
    config_path = Path(config_path)
    if config_path.is_dir():
        findings: list[Finding] = []
        for rel in (*HARNESS_FILES.values(), *_MCP_ONLY_FILES):
            path = config_path / rel
            if path.is_file():
                findings.extend(
                    Finding(f.severity, f.check, f"{rel}: {f.detail}") for f in scan(path)
                )
        return findings
    data = _load_json(config_path)
    return scan_data(data, detect_kind(config_path), _project_root(config_path))
