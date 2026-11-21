"""``admit serve``: one Starlette app with POST /check, /mcp gateway and dashboard routes.

The decision path is identical for every adapter: caller from the bearer
token -> built-in self-protection -> CEL policies -> audit entry -> verdict.
"""

from __future__ import annotations

from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse

from admit.config import AdmitConfig
from admit.types import Decision, ToolRequest


def create_app(config: AdmitConfig) -> Starlette:
    """Build the Starlette app: /check, /mcp gateway, dashboard routes."""
    raise NotImplementedError


async def check(request: Request) -> JSONResponse:
    """POST /check handler: resolve caller, self-protection, CEL, audit, verdict."""
    raise NotImplementedError


def _decision_to_dict(decision: Decision) -> dict[str, Any]:
    """Serialize a Decision for the hook / /check responses."""
    raise NotImplementedError


def _build_tool_request(
    caller: str, tool: str, args: dict[str, Any], model: str
) -> ToolRequest:
    """Build a ToolRequest from an adapter payload."""
    raise NotImplementedError
