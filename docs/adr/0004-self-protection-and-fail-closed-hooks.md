# 0004 — Built-in self-protection and fail-closed hooks

**Status:** Accepted

## Context

An agent that can edit its harness settings (`.gemini/`, `.claude/`, `.agents/`) can remove Admit
or add a direct MCP server. One that can edit `policies/` or `admit.yaml` can grant itself
anything. One that can read `.admit/keys/` can forge audit receipts, and one that can read `.env*`
can leak secrets. These rules cannot live in a policy file the agent might be able to change.

Harness hooks are how built-in tools reach Admit. In Gemini CLI 0.70 only exit code 2 blocks a
tool; any other non-zero exit is a warning and the tool runs, and non-JSON stdout is treated as
allow. Claude Code hooks behave the same way. An ordinary crash in a hook therefore fails open.

## Decision

- Self-protection is code (`admit/selfprotect.py`), not YAML. It is evaluated before every policy,
  in enforce and audit mode, and no policy can override it.
  - Deny writes to `.gemini/`, `.agents/`, `.claude/`, `policies/`, `.admit/`, `admit.yaml`.
  - Deny reads of `.admit/keys/` and `.env*`.
  - Paths are resolved against the workspace first (`..`, absolute paths, both slash styles,
    case-insensitive on Windows, symlinks).
- `admit hook` catches everything (`except BaseException`), writes only JSON to stdout, and turns
  every failure into a deny with exit code 2: invalid input, unknown tool, unreachable
  `admit serve`, internal error.

## Consequences

- **Self-protection cannot see inside shell commands.** `type .env`, `python -c "open('.env')"`
  or a script that reads files are not path-checked. For `shell.run`, only the exact-command
  allowlist protects these paths. We do not claim more than that.
- A hook command that never starts (interpreter missing, bad path) exits with whatever the OS
  returns, which the harness may treat as allow. Hook timeouts are harness-defined. Both are
  tested and documented in the README; where they fail open we say so.
- Changing protected paths requires editing them outside the agent, by a human.
