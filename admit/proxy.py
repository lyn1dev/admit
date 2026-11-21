"""MCP gateway: HTTP in from the agent, stdio out to fs + shell servers.

One FastMCP app exposes ``admit.yaml`` upstreams as namespaced tools, with
policy middleware that calls POST /check before any downstream call.
"""

from __future__ import annotations

from fastmcp import FastMCP

from admit.config import AdmitConfig


def build_gateway(
    config: AdmitConfig,
    policies: object,
    audit: object,
    sink: object,
) -> FastMCP:
    """Build the gateway: middleware + mounted upstreams + bearer-token auth."""
    raise NotImplementedError
