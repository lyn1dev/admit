# 0001 — Enforce policy at the MCP boundary

**Status:** Accepted

## Context

An agent can reach tools three ways: through an MCP client, through a
provider's built-in tools (Gemini CLI's `read_file`, `run_shell_command`), or by
shelling out itself. Any control that lives inside the agent is advisory: a
prompt injection rewrites the agent's instructions, but it cannot rewrite the
process that mediates tool calls. We need one place where every call is
intercepted, decided, and logged, and it must sit outside the model.

## Decision

Admit is an MCP proxy. The agent is configured with exactly one server, Admit,
which speaks MCP to the agent and MCP to the real servers. Tool names are
namespaced (`fs.read_text_file`, `shell.run`), every call is evaluated against
CEL policies, and only allowed calls are forwarded. Denials are returned as a
normal MCP tool result carrying `{"admit": {"decision": "DENY", ...}}` plus a
hint telling the model to continue without the step and report the block.

## Consequences

- One integration point: new servers are added to Admit's config, not to the
  agent, and the policy is independent of the model or client.
- The proxy sees names and arguments but not the model's reasoning, so policy
  must be written against call shape, not intent.
- **Built-in harness tools bypass the proxy and must be disabled.** If the
  client still exposes its own file or shell tools, the demo's guarantees do
  not hold. That exclusion is configured per client; see
  `docs/dev/api-notes.md`.
- Latency and a single point of failure are added to every tool call; Admit
  fails closed, so its downtime is the agent's downtime.
- Servers that require a stdio transport need a bridge; the prototype targets
  HTTP MCP servers.
