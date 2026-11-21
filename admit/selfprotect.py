"""Built-in self-protection: always-on rules no policy file can override.

Evaluated before every other policy, in both enforce and audit mode. Matches
here are DENY that nothing can override. Pure: no MCP, no network, no model
calls, so every rule is unit-testable.

Limit (ADR-0004): it cannot see inside shell commands. For ``shell.run`` only
the exact-command allowlist protects these paths -- never claim more.
"""

from __future__ import annotations

from pathlib import Path

from admit.types import Decision, ToolRequest

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

# Paths no tool may read. ``.env*`` covers ``.env``, ``.env.local``, etc.
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
        "builtin.view_file",
        "builtin.read_file",
    }
)

WRITE_VERBS: tuple[str, ...] = (
    "write", "edit", "replace", "create", "delete", "move", "rename", "sed"
)


def resolve_path(path: str, workspace: Path) -> Path:
    """Resolve ``path`` against ``workspace``.

    Handles ``..`` segments, absolute paths, both slash styles and symlinks,
    then returns the path relative to the workspace (for matching).
    """
    raise NotImplementedError


def check(request: ToolRequest, workspace: Path) -> Decision | None:
    """Return a DENY decision for a self-protection match, else ``None``.

    ``None`` means no self-protection rule matched and other policies may
    decide. A match denies even in audit mode.
    """
    raise NotImplementedError
