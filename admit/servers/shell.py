"""Shell MCP server: one tool run(command), fixed cwd, 30 s timeout.

Launched only by Admit (stdio) with a scrubbed environment -- it never
inherits GOOGLE_API_KEY or any other upstream credential.
"""

from __future__ import annotations

import argparse
import subprocess
from typing import Any

from fastmcp import FastMCP

TIMEOUT_S = 30
MAX_OUTPUT_CHARS = 20_000

# Set from --cwd in __main__; Admit fixes it per upstream, the agent cannot move it.
WORKDIR = "."

mcp = FastMCP("shell")


@mcp.tool
def run(command: str) -> dict[str, Any]:
    """Run one shell command in the fixed working directory."""
    try:
        completed = subprocess.run(
            command,
            shell=True,
            cwd=WORKDIR,
            timeout=TIMEOUT_S,
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": f"timed out after {TIMEOUT_S} s",
        }
    return {
        "exit_code": completed.returncode,
        "stdout": (completed.stdout or "")[:MAX_OUTPUT_CHARS],
        "stderr": (completed.stderr or "")[:MAX_OUTPUT_CHARS],
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="admit.servers.shell")
    parser.add_argument("--cwd", default=".", help="working directory for every command")
    return parser.parse_args(argv)


if __name__ == "__main__":
    WORKDIR = _parse_args().cwd
    mcp.run()
