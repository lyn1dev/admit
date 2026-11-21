"""Built-in self-protection: always-on rules no policy file can override.

Evaluated before every other policy, in both enforce and audit mode. Matches
here are DENY that nothing can override. Pure: no MCP, no network, no model
calls, so every rule is unit-testable.

Limit (ADR-0004): it cannot see inside shell commands. For ``shell.run`` only
the exact-command allowlist protects these paths -- never claim more.
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from admit.types import Decision, ToolRequest, Verdict

POLICY_NAME = "admit-self-protection"

# Harness-relative paths no tool may ever write. Matched case-insensitively on
# Windows, against the resolved workspace path.
PROTECTED_WRITE_PATHS: tuple[str, ...] = (
    ".gemini/",
    ".agents/",
    ".claude/",
    ".pi/",
    "policies/",
    ".admit/",
    "admit.yaml",
)

# Global harness config outside the workspace: the agent must not edit or
# remove Admit from here either.
GLOBAL_PROTECTED_WRITE_PATHS: tuple[str, ...] = (
    "~/.gemini/config/",
    "~/.gemini/antigravity-cli/",
)

# Paths no tool may read. A trailing slash is a workspace-relative directory;
# anything else is a glob on the file name. ``.env*`` covers ``.env``,
# ``.env.local``, ``.env.production``, ...
PROTECTED_READ_PATTERNS: tuple[str, ...] = (
    ".admit/keys/",
    ".env*",
)

# MCP policy-tool names (built-ins are mapped onto these by admit.hook).
WRITE_TOOLS: frozenset[str] = frozenset(
    {
        "fs.create_file",
        "fs.write_file",
        "fs.edit_file",
        "fs.delete",
        "fs.move",
        "builtin.write_to_file",
        "builtin.replace_file_content",
        "builtin.multi_replace_file_content",
        "builtin.sed_file",
    }
)

READ_TOOLS: frozenset[str] = frozenset(
    {
        "fs.read_text_file",
        "fs.read_file",
        "fs.read_media_file",
        "fs.list_directory",
        "fs.search_files",
        "fs.directory_tree",
        "builtin.view_file",
        "builtin.read_file",
        "builtin.list_dir",
        "builtin.find_by_name",
        "builtin.grep_search",
    }
)

WRITE_VERBS: tuple[str, ...] = (
    "write",
    "edit",
    "replace",
    "create",
    "delete",
    "move",
    "rename",
    "sed",
)

# Argument keys that carry a filesystem path (slash- or backslash-separated).
PATH_ARG_KEYS: tuple[str, ...] = (
    "path",
    "file_path",
    "filePath",
    "file_paths",
    "dir_path",
    "dirPath",
    "source",
    "destination",
    "paths",
    "Path",
    "AbsolutePath",
    "TargetFile",
    "DirectoryPath",
    "SearchPath",
)


# -- path resolution --------------------------------------------------------


def resolve_path(path: str, workspace: Path) -> Path:
    """Resolve ``path`` to an absolute path.

    Expands ``~``, accepts both slash styles, joins a relative path onto
    ``workspace``, then resolves ``..`` segments and symlinks with
    ``os.path.realpath``. The result is absolute; the workspace and the home
    directory are the only bases.
    """
    text = os.path.expanduser(str(path).strip())
    text = _native_separators(text)
    candidate = Path(text)
    if not candidate.is_absolute():
        candidate = Path(os.path.abspath(str(workspace))) / candidate
    return Path(os.path.realpath(str(candidate)))


def _native_separators(text: str) -> str:
    """Accept both slash styles: the agent may send ``C:/x`` or ``C:\\x``."""
    return text.replace("/", os.sep) if os.sep == "\\" else text.replace("\\", "/")


def _norm(path: Path) -> str:
    """Case-insensitive on every platform (fail closed).

    Windows and default macOS file systems ignore case, so ``ADMIT.YAML`` *is*
    ``admit.yaml`` there; on case-sensitive Linux this only over-protects.
    """
    return os.path.normcase(os.path.abspath(str(path))).casefold()


def _within(child: Path, root: Path) -> bool:
    """True if ``child`` is ``root`` or lives under it."""
    child_text = _norm(child)
    root_text = _norm(root).rstrip(os.sep)
    return child_text == root_text or child_text.startswith(root_text + os.sep)


def _write_roots(workspace: Path) -> list[Path]:
    roots = [
        Path(os.path.realpath(str(Path(workspace) / entry))) for entry in PROTECTED_WRITE_PATHS
    ]
    roots.extend(
        Path(os.path.realpath(os.path.expanduser(entry))) for entry in GLOBAL_PROTECTED_WRITE_PATHS
    )
    return roots


def _read_rules(workspace: Path) -> tuple[list[Path], list[str]]:
    roots: list[Path] = []
    patterns: list[str] = []
    for entry in PROTECTED_READ_PATTERNS:
        if entry.endswith("/"):
            roots.append(Path(os.path.realpath(str(Path(workspace) / entry))))
        else:
            patterns.append(entry)
    return roots, patterns


# -- rules ------------------------------------------------------------------


def check(request: ToolRequest, workspace: Path) -> Decision | None:
    """Return a DENY decision for a self-protection match, else ``None``.

    ``None`` means no self-protection rule matched and other policies may
    decide. A match denies even in audit mode; a path that cannot be resolved
    also denies (fail closed). ``shell.run`` and any other tool without a path
    argument never matches: only the shell allowlist can protect these paths.
    """
    try:
        return _check(request, Path(workspace))
    except Exception as exc:  # noqa: BLE001 - fail closed on anything
        return Decision(
            Verdict.DENY,
            POLICY_NAME,
            f"admit self-protection error: {type(exc).__name__}: {exc}",
        )


def _check(request: ToolRequest, workspace: Path) -> Decision | None:
    tool = str(request.tool)
    writes = _is_write_tool(tool)
    reads = tool in READ_TOOLS
    if not (writes or reads):  # includes shell.run: not path-checkable (ADR-0004)
        return None

    write_roots = _write_roots(workspace) if writes else []
    read_roots, read_patterns = _read_rules(workspace) if reads else ([], [])
    for raw in _path_values(request.args):
        target = _resolve_argument(raw, workspace)
        if target is None:
            return Decision(
                Verdict.DENY,
                POLICY_NAME,
                f"admit self-protection: cannot resolve path argument {raw!r} for {tool}",
            )
        if writes and any(_within(target, root) for root in write_roots):
            return Decision(
                Verdict.DENY,
                POLICY_NAME,
                f"admit self-protection: {tool} may not write to {raw}",
            )
        if reads and _is_protected_read(target, str(raw), read_roots, read_patterns):
            return Decision(
                Verdict.DENY,
                POLICY_NAME,
                f"admit self-protection: {tool} may not read {raw}",
            )
    return None


def _is_protected_read(target: Path, raw: str, roots: list[Path], patterns: list[str]) -> bool:
    """Protected read roots, plus file-name patterns on the raw and resolved path.

    ``fnmatch.fnmatch`` folds case on Windows only, which is exactly the rule.
    """
    if any(_within(target, root) for root in roots):
        return True
    names = {target.name, raw.replace("\\", "/").rsplit("/", 1)[-1]}
    return any(fnmatch.fnmatch(name, pattern) for name in names for pattern in patterns)


def _is_write_tool(tool: str) -> bool:
    """A write tool by name, or any tool whose bare name carries a write verb."""
    if tool in WRITE_TOOLS:
        return True
    bare = tool.rsplit(".", 1)[-1].lower()
    return any(verb in bare for verb in WRITE_VERBS)


def _path_values(args: dict[str, Any]) -> Iterator[Any]:
    """Yield every path-like argument value (flattening list-valued keys)."""
    if not isinstance(args, dict):
        return
    for key in PATH_ARG_KEYS:
        if key not in args:
            continue
        value = args[key]
        if isinstance(value, (list, tuple)):
            yield from value
        else:
            yield value


def _resolve_argument(raw: Any, workspace: Path) -> Path | None:
    if isinstance(raw, Path):
        raw = str(raw)
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        return resolve_path(raw, workspace)
    except (OSError, ValueError):
        return None


__all__ = [
    "GLOBAL_PROTECTED_WRITE_PATHS",
    "PATH_ARG_KEYS",
    "POLICY_NAME",
    "PROTECTED_READ_PATTERNS",
    "PROTECTED_WRITE_PATHS",
    "READ_TOOLS",
    "WRITE_TOOLS",
    "WRITE_VERBS",
    "check",
    "resolve_path",
]
