"""``admit hook``: BeforeTool/PreToolUse hook for Antigravity, Gemini CLI, Claude Code.

Reads one harness tool call from stdin, maps it onto the shared policy tool
names, decides via ``POST /check`` to ``admit serve``, and prints harness-
specific output. Fail-closed: any error exits 2, nothing but JSON is ever
written to stdout, and ``main`` wraps everything in ``except BaseException``.
"""

from __future__ import annotations

import sys
from typing import Any

from admit.types import Decision, ToolRequest

# Antigravity CLI (args are PascalCase; only run_command/CommandLine is
# confirmed by Google's hook docs -- the rest are expected names, to confirm
# with the M0 tap hook). Value: (policy tool, harness arg key -> policy arg key).
ANTIGRAVITY_TOOL_MAP: dict[str, tuple[str, dict[str, str]]] = {
    "run_command": ("shell.run", {"CommandLine": "command"}),
    "view_file": ("fs.read_text_file", {"path": "path"}),
    "write_to_file": ("fs.write_file", {"path": "path"}),
    "replace_file_content": ("fs.edit_file", {"path": "path"}),
    "multi_replace_file_content": ("fs.edit_file", {"path": "path"}),
    "list_dir": ("fs.list_directory", {"path": "path"}),
    "find_by_name": ("fs.search_files", {"path": "path"}),
    "grep_search": ("fs.search_files", {"path": "path"}),
    "read_url_content": ("net.fetch", {"Url": "url"}),
    "search_web": ("net.search", {"query": "query"}),
}

# Gemini CLI built-ins (file_path / dir_path / url / query keys).
GEMINI_TOOL_MAP: dict[str, tuple[str, dict[str, str]]] = {
    "run_shell_command": ("shell.run", {"command": "command"}),
    "read_file": ("fs.read_text_file", {"file_path": "path"}),
    "read_many_files": ("fs.read_text_file", {"file_path": "path"}),
    "write_file": ("fs.write_file", {"file_path": "path"}),
    "replace": ("fs.edit_file", {"file_path": "path"}),
    "list_directory": ("fs.list_directory", {"dir_path": "path"}),
    "glob": ("fs.search_files", {"path": "path"}),
    "grep_search": ("fs.search_files", {"path": "path"}),
    "web_fetch": ("net.fetch", {"url": "url"}),
    "google_web_search": ("net.search", {"query": "query"}),
}

# Claude Code: same mapping shape; confirm its built-in names from its hook
# docs before filling this in.
CLAUDE_TOOL_MAP: dict[str, tuple[str, dict[str, str]]] = {}

TOOL_MAPS: dict[str, dict[str, tuple[str, dict[str, str]]]] = {
    "antigravity": ANTIGRAVITY_TOOL_MAP,
    "gemini": GEMINI_TOOL_MAP,
    "claude": CLAUDE_TOOL_MAP,
}

# Tools the proxy already checked (MCP passthrough) -- skip re-mapping here.
PASSTHROUGH_PREFIXES = ("mcp_admit_",)


def map_call(harness: str, payload: dict[str, Any]) -> list[ToolRequest]:
    """Map one harness tool call (stdin payload) onto ToolRequest policy calls.

    One built-in call can become several requests (e.g. read_many_files: one
    check per path). Unknown tools map to ``builtin.<name>`` with raw args so
    default-deny applies unless a policy grants them.
    """
    raise NotImplementedError


def check_remote(requests: list[ToolRequest], server_url: str, token: str) -> Decision:
    """POST the mapped requests to ``admit serve`` and return the Decision.

    Unreachable server, invalid response or any transport error returns DENY
    (fail closed). Token read from ``ADMIT_TOKEN`` or ``.admit/hook-token``.
    """
    raise NotImplementedError


def render_deny(harness: str, decision: Decision) -> tuple[str, int]:
    """Return ``(stdout, exit_code)`` for a deny decision.

    Antigravity: ``{"decision": "deny", "reason": "..."}`` on stdout. The exit
    code (0 or 2) is decided by the M3 hook-failure matrix
    (docs/dev/hook-behaviour.md, plan section 2). Gemini CLI / Claude Code:
    exit 2, reason on stderr (any other non-zero exit fails open there).
    """
    raise NotImplementedError


def main(harness: str) -> None:
    """Entry point for ``admit hook --harness <harness>``.

    Fail-closed rule: exit 2 on any error, nothing but JSON on stdout, and the
    whole body wrapped in ``except BaseException`` so even an unexpected crash
    denies instead of failing open.
    """
    raise NotImplementedError


if __name__ == "__main__":
    # Usage: python -m admit.hook antigravity < payload.json
    main(sys.argv[1] if len(sys.argv) > 1 else "antigravity")
