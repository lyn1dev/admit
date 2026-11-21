"""MCP gateway: HTTP in from the agent, stdio out to fs + shell servers.

One FastMCP app exposes ``admit.yaml`` upstreams as namespaced tools
(``fs_*``, ``shell_*``), with policy middleware that runs the same decision
path as ``POST /check`` before any downstream call is made.

Upstreams are launched here and nowhere else, each with a scrubbed environment:
only a fixed allowlist of OS variables plus that upstream's own ``env`` from
``admit.yaml``. Credentials of one upstream never reach another (or the agent).
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from fastmcp import FastMCP
from fastmcp.client.transports import StdioTransport
from fastmcp.server import create_proxy
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.base import Tool, ToolResult

from admit import pins as pinning
from admit.config import AdmitConfig
from admit.decision import DecisionPoint, caller_for_token
from admit.redact import redact
from admit.types import Decision, ToolRequest, Verdict, normalize_tool

# The only inherited variables an upstream may see. Everything else (API keys,
# tokens, proxies, .env-loaded values) is dropped.
ALLOWED_ENV_VARS: tuple[str, ...] = (
    "PATH",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PATHEXT",
    "COMSPEC",
    "WINDIR",
    "LANG",
)

TokenGetter = Callable[[], str]


def scrubbed_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Allowlisted OS environment, plus ``UV_*``, plus this upstream's own env."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key in ALLOWED_ENV_VARS or key.startswith("UV_")
    }
    if extra:
        env.update(extra)
    return env


def _http_token() -> str:
    """The inbound ``Authorization`` header, if the caller came over HTTP."""
    try:
        headers = get_http_headers(include={"authorization"})
    except Exception:  # noqa: BLE001 - no HTTP request: treated as anonymous
        return ""
    return headers.get("authorization", "")


def _error_result(decision: Decision) -> ToolResult:
    """A structured, explained denial the agent can act on."""
    payload = decision.to_agent_error()
    return ToolResult(
        content=[{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
        structured_content=payload,
        is_error=True,
    )


def _is_text_block(block: Any) -> bool:
    if isinstance(block, dict):
        return block.get("type") == "text" and isinstance(block.get("text"), str)
    return getattr(block, "type", None) == "text" and isinstance(
        getattr(block, "text", None), str
    )


def _with_text(block: Any, text: str) -> Any:
    if isinstance(block, dict):
        return {**block, "text": text}
    return block.model_copy(update={"text": text})


def _redact_value(value: Any) -> tuple[Any, int]:
    """Recursively redact every string in a JSON-ish structure."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        total = 0
        out: dict[Any, Any] = {}
        for key, item in value.items():
            out[key], hits = _redact_value(item)
            total += hits
        return out, total
    if isinstance(value, list):
        total = 0
        items = []
        for item in value:
            redacted_item, hits = _redact_value(item)
            total += hits
            items.append(redacted_item)
        return items, total
    return value, 0


def redact_result(result: ToolResult) -> ToolResult:
    """Redact secrets in every text block and in ``structured_content``.

    The count is the larger of the two views rather than their sum: an upstream
    dict is rendered both as JSON text and as structured content, so the same
    secret normally appears twice.
    """
    text_total = 0
    content: list[Any] = []
    for block in result.content:
        if not _is_text_block(block):
            content.append(block)
            continue
        text, hits = redact(block["text"] if isinstance(block, dict) else block.text)
        text_total += hits
        content.append(_with_text(block, text))

    structured, structured_total = _redact_value(result.structured_content)
    total = max(text_total, structured_total)
    if total:
        if not isinstance(structured, dict):
            structured = {}
        structured["redacted"] = total
        content.append({"type": "text", "text": f"admit: redacted {total} secret(s)"})

    result.content = content
    result.structured_content = structured
    return result


class AdmitMiddleware(Middleware):
    """Bearer-token identity, the shared decision path, pins and redaction."""

    def __init__(
        self,
        config: AdmitConfig,
        decision_point: DecisionPoint,
        *,
        pins_path: Path | None = None,
        pin: bool = False,
        token_getter: TokenGetter | None = None,
    ) -> None:
        self.config = config
        self.decision_point = decision_point
        self.pins_path = Path(pins_path) if pins_path is not None else None
        self.pin = pin
        self.token_getter = token_getter or _http_token
        self._mismatched: set[str] = set()

    # -- tools/list: pinning ---------------------------------------------

    async def on_list_tools(
        self,
        context: MiddlewareContext[Any],
        call_next: Callable[[MiddlewareContext[Any]], Any],
    ) -> Sequence[Tool]:
        tools = list(await call_next(context))
        if self.pins_path is None:
            return tools

        current = {
            tool.name: pinning.tool_digest(
                tool.name, tool.description or "", tool.parameters or {}
            )
            for tool in tools
        }
        pinned = pinning.load_pins(self.pins_path)
        if self.pin or not pinned:
            # First run (or an explicit re-approval): record what we see.
            pinning.save_pins(self.pins_path, {**pinned, **current})
            self._mismatched = set()
            return tools

        self._mismatched = pinning.compare(current, pinned)
        if not self._mismatched:
            return tools
        # A tool whose definition changed is not shown to the agent at all.
        return [tool for tool in tools if tool.name not in self._mismatched]

    # -- tools/call: decide, forward, redact ------------------------------

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: Callable[[MiddlewareContext[Any]], Any],
    ) -> ToolResult:
        message = context.message
        name = getattr(message, "name", "") or ""
        arguments = getattr(message, "arguments", None) or {}

        auth = self.token_getter() or ""
        caller = caller_for_token(self.config, auth)
        if caller is None:
            # Unknown or missing token: the upstream is never contacted.
            return _error_result(
                Decision(
                    Verdict.DENY,
                    None,
                    "unauthorized: missing or unknown bearer token",
                    "Configure the agent with a valid Admit token from admit.yaml.",
                )
            )

        request = ToolRequest(
            caller=caller,
            tool=normalize_tool(name),
            args=dict(arguments),
            model="",
        )

        if self.pins_path is not None and name in self._mismatched:
            decision = Decision(
                Verdict.PIN_MISMATCH,
                None,
                f"tool definition changed since it was pinned: {name}",
                "Run `admit serve --pin` to review and re-approve the tool.",
            )
            return _error_result(self.decision_point.record(request, decision))

        decision = await self.decision_point.decide(request)
        if not decision.allowed:
            return _error_result(decision)

        try:
            result = await call_next(context)
        except Exception as exc:  # noqa: BLE001 - an upstream failure is a denial
            return _error_result(
                Decision(
                    Verdict.DENY,
                    decision.policy,
                    f"upstream error: {type(exc).__name__}: {exc}",
                )
            )
        return redact_result(result)


def build_gateway(
    config: AdmitConfig,
    decision_point: DecisionPoint,
    *,
    pins_path: Path | None = None,
    pin: bool = False,
    token_getter: TokenGetter | None = None,
) -> FastMCP:
    """Build the gateway: middleware + mounted upstreams + bearer-token auth."""
    gateway = FastMCP(
        "admit",
        middleware=[
            AdmitMiddleware(
                config,
                decision_point,
                pins_path=pins_path,
                pin=pin,
                token_getter=token_getter,
            )
        ],
    )
    for name, upstream in config.upstreams.items():
        transport = StdioTransport(
            command=upstream.command,
            args=list(upstream.args),
            env=scrubbed_env(upstream.env),
            cwd=upstream.cwd,
        )
        gateway.mount(create_proxy(transport), namespace=name)
    return gateway
