# Antigravity adapter

- `hooks.json`: template for `<workspace>/.agents/hooks.json`. `admit init antigravity` fills in
  `{ADMIT_PROJECT}` with the absolute path of the Admit checkout. `demo-repo/.agents/hooks.json`
  is the ready-made demo copy (relative path, since the hook's working directory is `.agents/`).
- `tap.py`: M0 helper that logs real `PreToolUse` payloads and allows everything. Scratch folders only.

Auth: sign in to `agy` with your Google account. Do not set `modelProvider` in
`~/.gemini/antigravity-cli/settings.json`; that switches `agy` to `GEMINI_API_KEY` and its rate limits.
See docs/dev/api-notes.md section 9.
