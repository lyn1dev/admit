"""``admit serve``: one Starlette app with POST /check, /mcp gateway and dashboard routes.

The decision path is identical for every adapter: caller from the bearer
token -> built-in self-protection -> CEL policies -> audit entry -> verdict.
"""

from __future__ import annotations

from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from admit.config import AdmitConfig
from admit.decision import DecisionPoint, caller_for_token
from admit.types import Decision, ToolRequest, Verdict, normalize_tool


def create_app(
    config: AdmitConfig,
    decision_point: DecisionPoint,
    gateway: Any,
) -> Starlette:
    """Build the Starlette app: /check, /mcp gateway, dashboard routes.

    The gateway's own ASGI app is mounted at the root so its ``/mcp`` path is
    served as ``/mcp`` (mounting it under ``/mcp`` would give ``/mcp/mcp``), and
    its lifespan is handed to the parent: without it the streamable-HTTP session
    manager never starts and every request 500s.
    """
    mcp_app = gateway.http_app(path="/mcp")
    app = Starlette(
        routes=[
            Route("/check", check, methods=["POST"]),
            Mount("/", app=mcp_app),
        ],
        lifespan=mcp_app.lifespan,
    )
    app.state.config = config
    app.state.decision_point = decision_point
    return app


async def check(request: Request) -> JSONResponse:
    """POST /check handler: resolve caller, self-protection, CEL, audit, verdict."""
    config: AdmitConfig = request.app.state.config
    decision_point: DecisionPoint = request.app.state.decision_point

    caller = caller_for_token(config, request.headers.get("authorization", ""))
    if caller is None:
        return JSONResponse(
            {"error": "unauthorized", "reason": "missing or unknown bearer token"},
            status_code=401,
        )

    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - any unparsable body is a client error
        return _bad_request("malformed request body: expected JSON")

    if not isinstance(body, dict):
        return _bad_request("malformed request body: expected a JSON object")

    tool = body.get("tool")
    if not isinstance(tool, str) or not tool.strip():
        return _bad_request("missing 'tool' (the policy tool name, e.g. shell.run)")

    args = body.get("args")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return _bad_request("'args' must be a JSON object")

    model = body.get("model") or ""
    if not isinstance(model, str):
        model = ""

    decision = await decision_point.decide(
        _build_tool_request(caller, tool, args, model)
    )
    return JSONResponse(_decision_to_dict(decision))


def _bad_request(reason: str) -> JSONResponse:
    """A 400 that still carries the DENY shape adapters already parse."""
    body = _decision_to_dict(Decision(Verdict.DENY, None, reason))
    body["error"] = reason
    return JSONResponse(body, status_code=400)


def _decision_to_dict(decision: Decision) -> dict[str, Any]:
    """Serialize a Decision for the hook / /check responses."""
    return {
        "decision": decision.verdict.value,
        "policy": decision.policy,
        "reason": decision.reason,
        "hint": decision.hint,
        "allowed": decision.allowed,
    }


def _build_tool_request(
    caller: str, tool: str, args: dict[str, Any], model: str
) -> ToolRequest:
    """Build a ToolRequest from an adapter payload."""
    return ToolRequest(
        caller=caller, tool=normalize_tool(tool), args=dict(args), model=model
    )
