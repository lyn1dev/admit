# Hook-failure behaviour (plan section 2, item 2)

Template for the harness failure matrix. Each case is reproduced against
`agy -p` (headless) and the interactive Antigravity TUI; every cell starts as
"TBD" and is filled in at M3, before the hook is trusted. The exit-code
behaviour below follows Antigravity's documented rule: `decision: "deny"` is a
hard block; hook *failure* (non-zero exit, no output, non-JSON, timeout,
failed start) is undocumented and must be tested -- in Gemini CLI 0.70 anything
other than exit 2 and non-JSON stdout is treated as **allow**.

| # | Case | `agy -p` result | TUI result | Blocks? | Notes |
|---|------|-----------------|------------|---------|-------|
| (a) | deny JSON + exit 0 | TBD | TBD | TBD | Some harnesses treat exit 0 + any stdout as allow |
| (b) | deny JSON + exit 2 | TBD | TBD | TBD | intended fail-closed behaviour |
| (c) | exit 1, no output | TBD | TBD | TBD | |
| (d) | non-JSON stdout | TBD | TBD | TBD | non-JSON stdout may be treated as allow |
| (e) | hook sleeps past timeout | TBD | TBD | TBD | hook timeout must exceed warn.timeout_seconds |
| (f) | command cannot start (e.g. `uv` missing) | TBD | TBD | TBD | |

Each row must be reproduced for `run_command`, `view_file`, `write_to_file` and one
MCP tool (`fs.read_text_file`). Record the observation here and in the README.
If any case fails open, say so plainly and add `permissions.deny` rules in
`~/.gemini/antigravity-cli/settings.json` as a second layer. Hook settings live
in files guarded by self-protection, so the agent cannot remove them.
