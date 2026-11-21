# Hook-failure behaviour (plan section 2, item 2)

## Antigravity CLI (`agy` 1.5.14, Windows) — tested 2026-11-21

Method: one scratch folder per case with a `.agents/hooks.json` (`"matcher": "*"`, `timeout: 5`)
pointing at a fake hook; `agy -p --model gemini-3.8-flash-low` was asked to run
`python -c "open('ran.txt','w').write('x')"`. "Ran" = `ran.txt` exists afterwards.

| # | Case | `agy -p` result | Ran? | What the model saw |
|---|------|-----------------|------|--------------------|
| (a) | deny JSON + exit 0 | blocked | no | `tool call denied by pre-tool hook: <our reason>` |
| (b) | deny JSON + exit 2 | blocked | no | `JSON hook ... failed: command failed: exit status 2` (our reason lost) |
| (c) | exit 1, no output | blocked | no | `... exit status 1` |
| (d) | non-JSON stdout, exit 0 | blocked | no | `failed to unmarshal result from hook ... invalid value` |
| (e) | hook sleeps past timeout | blocked | no | `... command failed: exit status 1` |
| (f) | command cannot start | blocked | no | `'...' is not recognized as an internal or external command` |

**Every failure mode fails closed in `agy -p`.** Consequences for `admit hook --harness antigravity`:
a policy deny prints `{"decision": "deny", "reason": ...}` with **exit 0** (case a: the only case
where the model sees Admit's reason); internal errors exit 2 (still blocks). No
`permissions.deny` second layer is needed for headless runs.

Not tested yet: the interactive TUI, and how several `PreToolUse` hooks (e.g. a global
`~/.gemini/config/hooks.json`) combine.

## Gemini CLI 0.70 — from its bundled docs (`docs/hooks/reference.md`)

| Exit code | Effect |
|---|---|
| 0 | stdout parsed as JSON; `{"decision": "deny", "reason": ...}` blocks, reason goes to the agent |
| 2 | blocks; stderr is the reason |
| anything else | **warning only, the tool runs (fails open)** |

`admit hook --harness gemini` therefore answers a policy deny with exit 0 + deny JSON (clean
output, verified live) and every internal error with exit 2. Not tested: a hook command that
cannot start or that times out (default 60 s) — both are likely to fail **open** in Gemini CLI.
Keep `uv` on PATH and `admit serve` running; the demo hook timeout is 75 s, above the 60 s WARN hold.
