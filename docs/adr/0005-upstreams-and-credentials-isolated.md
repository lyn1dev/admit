# 0005 — Upstreams and credentials are isolated from the agent

**Status:** Accepted

## Context

A policy gateway is only a boundary if the agent cannot go around it. If the agent's config still
lists a tool server, or the agent's environment holds that server's token, the agent (or a prompt
injection steering it) can reach the tool directly. Secrets can also leak the other way: through
tool output, or through environment variables a child process inherits.

## Decision

- Downstream MCP servers are launched by Admit, over stdio, and by nothing else. `admit init`
  moves them out of the agent's config into `admit.yaml`; `admit posture` flags any server the
  agent can still reach without Admit.
- Downstream credentials live only in `admit.yaml` (`upstreams.<name>.env`, referencing Admit's
  own environment). They are never written to the agent's config or environment.
- Upstreams start with a scrubbed environment: an allowlist (`PATH`, `SYSTEMROOT`, `TEMP`, ...)
  plus their own configured variables. The shell server does not inherit `GOOGLE_API_KEY` or any
  other Admit secret.
- Secret patterns are redacted from every tool result before it reaches the agent, and the result
  states how many values were removed.

## Consequences

- The agent sees one MCP server (Admit) and no credentials.
- Redaction is pattern-based; an unusual secret format can slip through. Default-deny on reads of
  `.env*` and the exact shell allowlist are the primary controls; redaction is a backstop.
- Admit governs which actions run, not what an allowed program does internally. A no-network
  sandbox alongside Admit covers that gap.
