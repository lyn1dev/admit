# Gemini CLI settings for the demo

- `mcpServers.admit`: the only tool server. Every tool call goes through Admit.
- `tools.core: []`: turns off all of Gemini CLI's built-in tools (shell, file read/write,
  web fetch), so the agent cannot go around Admit.
- `model.name`: pinned to flash-lite; the default model often returns 503 under load.

Gemini CLI ignores project settings in untrusted folders. Run it with `--skip-trust`
(or trust the folder once). Authenticate with `GEMINI_API_KEY`; Google account sign-in
is no longer supported for individual accounts.
