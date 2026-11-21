"""Shell MCP server: one tool run(command), fixed cwd, 30 s timeout.

Launched only by Admit (stdio) with a scrubbed environment -- it never
inherits GOOGLE_API_KEY or any other upstream credential.
"""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

TIMEOUT_S = 30

mcp = FastMCP("shell")


@mcp.tool
def run(command: str) -> dict[str, Any]:
    """Run one shell command in the fixed working directory."""
    raise NotImplementedError


if __name__ == "__main__":
    mcp.run()
