# API notes — verified against the installed versions

Installed (checked via `importlib.metadata.version`): `fastmcp 4.2.4`, `mcp 2.3.0`, `cel-python 0.5.0`
(`import celpy`), `google-adk 2.15.0`, `google-genai 2.34.0`, `pynacl 1.6.2`, `pytest-bdd 9.0.1`,
Gemini CLI `0.70.0` (`npm root -g` → `@google/gemini-cli`). Python 3.12.10, uv 0.13.9.

Every snippet below was run unless marked `unverified`. Scratch scripts lived outside the repo
(`%TEMP%\admit-scratch\`), not committed.

## TL;DR gotchas

| # | Gotcha |
|---|--------|
| 1 | FastMCP v4 proxy lives in `fastmcp.server.providers.proxy`; the supported factory is `from fastmcp.server import create_proxy`. `FastMCP.as_proxy` is gone. |
| 2 | Namespacing separator is `_`, not `.`: `mount(..., namespace="fs")` → `fs_read_file`. Dots *are* legal in tool names and survive the wire, so you can force true `fs.read_file` names. |
| 3 | `get_http_headers()` **strips `authorization` by default**. Use `get_http_headers(include={"authorization"})` or you will never see the bearer token. |
| 4 | `Client(url, headers={...})` raises `TypeError` in 4.2.4. Use `Client(url, auth="token")` or `StreamableHttpTransport(url, headers=...)`. |
| 5 | cel-python: activation values must be `celpy.adapter.json_to_cel(...)`; a raw `dict` raises `CELEvalError`. `matches()` is `re.search`, not full match. Results are `celtypes.BoolType` (subclass of `int`, **not** `bool`). |
| 6 | ADK 2.15 deprecates `LoopAgent` / `SequentialAgent` (warns at construction) in favour of `google.adk.workflow.Workflow`; both still work. |
| 7 | Gemini CLI builds MCP tool FQNs as `mcp_<alias>_<tool>`; with Admit's `fs.read_file` you get `mcp_admit_fs.read_file`. `tools.core: []` is what kills all built-ins. |
| 8 | Gemini CLI **project** `.gemini/settings.json` is ignored in an untrusted folder — including a `folderTrust.enabled: false` inside it. Trust must come from the user settings file or `--skip-trust` / `GEMINI_CLI_TRUST_WORKSPACE=true`. |
| 9 | Antigravity `agy` cannot turn built-in tools off: the `PreToolUse` `"*"` hook in `.agents/hooks.json` is the only enforcement point. Hook exit-code/timeout behaviour is undocumented (section 9). Never set `modelProvider` (switches to the API key quota). |

## 1. FastMCP 4.2.4 proxy (multi-downstream + namespacing)

**verified** (in-memory `Client(proxy)`, `list_tools` + `call_tool`).

API: `create_proxy(target)` accepts a `Client`, transport, `FastMCP`, URL, script path, `MCPConfig`
object or plain `{"mcpServers": {...}}` dict. Compose backends with `FastMCP.mount(proxy, namespace=...)`
or give one dict with several servers.

```python
from fastmcp import Client, FastMCP
from fastmcp.server import create_proxy

CFG = {"mcpServers": {
    "fs":    {"command": "uv", "args": ["run", "python", r"C:\work\admit\fs_server.py"]},
    "shell": {"command": "uv", "args": ["run", "python", r"C:\work\admit\shell_server.py"]},
}}
front = FastMCP("admit")
front.mount(create_proxy({"mcpServers": {"fs": CFG["mcpServers"]["fs"]}}), namespace="fs")
front.mount(create_proxy({"mcpServers": {"shell": CFG["mcpServers"]["shell"]}}), namespace="shell")
# `create_proxy(CFG)` with 2+ servers gives the same `fs_*` / `shell_*` prefixes unaided
async with Client(front) as c:                        # in-memory, no sockets
    print(sorted(t.name for t in await c.list_tools()))
    print((await c.call_tool("fs_run", {"command": "ls"})).data)
# -> ['fs_echo', 'fs_run', 'shell_run.command']  (shell tool is literally "run.command"); -> ran: ls
```

Exact naming rules observed:

| Construction | Resulting tool name |
|---|---|
| `create_proxy({"mcpServers": {"fs": ...}})` — **one** server | `run` (no prefix) |
| `create_proxy({"mcpServers": {"fs": ..., "shell": ...}})` — **two+** servers | `fs_run`, `shell_run.command` (config key + `_`) |
| `front.mount(proxy, namespace="fs")` / `namespace="a.b"` | `fs_run` / `a.b_ping` (**dots in the namespace survive**) |
| `front.mount(proxy, namespace="fs", tool_names={"echo": "read_file"})` | `fs_read_file` (rename first, then namespace) |
| `front.mount(proxy, tool_names={"run": "shell.run"})` (no namespace) | `shell.run` |

So: default separator is `_`; dot names are fully supported (listed *and* callable, verified
`call_tool("shell.run", ...)` → `ran: ls`). For `fs.read_file` exactly, mount without a namespace and
rename — FastMCP never uses `.` on its own.

Runtime caveats: passing a **dict/config** to `create_proxy` logs `reusing existing session for all
requests...` (one stdio session per backend, `keep_alive=True`) — concurrent calls multiplex on it.
And `cwd` in an `mcpServers` entry changes uv's project discovery: a `cwd` outside the project fails
with `ModuleNotFoundError: No module named 'fastmcp'` (verified); keep `cwd` at the repo or pass
`uv run --project <repo> ...`.

## 2. FastMCP middleware: intercept, short-circuit, mutate, headers, HTTP

**verified** end-to-end over stdio *and* streamable HTTP (server log showed the token; client saw the
denial and the mutated result).

```python
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server import create_proxy
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult

class Policy(Middleware):
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        call = context.message                       # mcp_types.CallToolRequestParams
        name, args = call.name, call.arguments       # args is a mutable dict
        auth = get_http_headers(include={"authorization"}).get("authorization", "")
        # get_http_headers() strips authorization by default; include_all=True / get_http_request()
        # also work, but get_http_headers never raises when there is no HTTP request.

        if name.startswith("shell_") and auth != "Bearer s3cret":
            return ToolResult(                        # short-circuit: downstream is NOT called
                content=[{"type": "text", "text": "denied by policy"}],
                structured_content={"error": "denied", "policy": "deny-shell"},
                is_error=True,                        # -> CallToolResult.is_error for the client
            )
        result = await call_next(context)             # forward downstream
        if name.endswith("echo"):                     # post-process upstream result
            result.structured_content = {**(result.structured_content or {}), "admit": "post-processed"}
            result.content = [*result.content, {"type": "text", "text": "admit: post-processed"}]
        return result
mcp = FastMCP("admit", middleware=[Policy()])        # or mcp.add_middleware(Policy())
mcp.mount(create_proxy({"mcpServers": {
    "fs":    {"command": "uv", "args": ["run", "python", "fs_server.py"]},
    "shell": {"command": "uv", "args": ["run", "python", "shell_server.py"]},
}}))                                                  # -> fs_*, shell_* names
mcp.run(transport="http", host="127.0.0.1", port=8765, path="/mcp", show_banner=False)
```

Verified observations:
- `context.message.name` is the **final, namespaced** name (`shell_run.command`, `fs_echo`) because
  middleware sits above the proxy provider — exactly what CEL's `request.tool` should see.
- `context.message.arguments` is the live dict; mutating it changes what the backend receives
  (verified: `args["command"] = "SAFE:"+...` → backend saw `SAFE:ls`).
- Deny without a result: `raise ToolError("policy denied: shell disabled")` → client gets
  `is_error=True`, `content[0].text == "policy denied: shell disabled"`. Return a `ToolResult` for a
  structured, machine-readable denial; raise to simply fail the call.
- `MiddlewareContext` fields: `message`, `fastmcp_context`, `source`, `type`, `method`
  (`"tools/call"`), `timestamp`. HTTP: `run(transport="http", ..., path="/mcp")` logged
  `transport 'http' on http://127.0.0.1:8765/mcp`, and a raw `curl POST /mcp` `initialize` returned
  200. `streamable-http` is an alias; `http_app(path=...)` exists for ASGI mounting.

Client side (both verified to send `Authorization: Bearer s3cret`): `Client(url, auth="s3cret")` or
`Client(StreamableHttpTransport(url, headers={"Authorization": "Bearer s3cret"}))`.
`Client(url, headers={...})` → `TypeError: Client.__init__() got an unexpected keyword argument 'headers'`.

Windows dev note: a stale server keeps 8765 and the next `run` dies with `[winerror 10048]` —
`powershell -NoProfile -Command "Get-Process python | Stop-Process -Force"`.

## 3. Minimal FastMCP server over stdio + launching it as a downstream

**verified** — client listed `['run', 'echo']`, called it, got `structured_content={'result': ...}`:

```python
# shell_server.py
from fastmcp import FastMCP

mcp = FastMCP("shell")

@mcp.tool
def run(command: str) -> str:
    """Run a shell command."""
    return f"ran: {command}"

if __name__ == "__main__":
    mcp.run(transport="stdio")          # default transport is stdio anyway
```

Downstream shapes (both verified): `{"command": "uv", "args": ["run", "python", r"C:\repo\shell_server.py"]}`
and `{"command": "uv", "args": ["run", "--project", r"C:\repo", "python", "-m", "admit.servers.shell"]}`.
`-m` needs the module importable from the child's cwd **and** the project env: `uv run python -m pkgdemo`
with a cwd outside the project → `ModuleNotFoundError: No module named 'fastmcp'`; `--project <repo>`
(or `cwd` at the repo) fixes it.

## 4. Windows: does `npx` need `cmd /c`?

**verified** — no, with this toolchain. Both forms launched `@modelcontextprotocol/server-filesystem`
and returned the same 16 tools:
`{"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", dir]}` (OK) and
`{"command": "cmd", "args": ["/c", "npx", "-y", "@modelcontextprotocol/server-filesystem", dir]}` (OK).

Reason: `mcp 2.3.0` normalises commands on Windows — `mcp/os/win32/utilities.get_windows_executable_command()`
runs `shutil.which(command)` then tries `.cmd/.bat/.exe/.ps1`, spawning via `create_windows_process`
(Job Object). Same result with raw `mcp.client.stdio.stdio_client` + `StdioServerParameters`. Keep
`cmd /c npx` only as a fallback for older SDKs / odd PATH setups. First run needs a network download;
it is cached afterwards.

## 5. cel-python 0.5.0 — compile, evaluate, fail-closed

**verified** (all expressions below evaluated; failures reproduced):

```python
import celpy
from celpy import celtypes
from celpy.adapter import json_to_cel

env = celpy.Environment()
prog = env.program(env.compile('request.tool.matches("^fs[._](read|write)_")'))   # compile ONCE

def evaluate(prog, request: dict) -> bool:
    """Fail-closed: anything other than a CEL bool is a policy error."""
    try:
        out = prog.evaluate({"request": json_to_cel(request)})   # json_to_cel is mandatory
    except Exception:                                            # CELParseError / CELEvalError
        return False
    if not isinstance(out, celtypes.BoolType):                   # e.g. int, string, map
        return False
    return bool(out)
```

| Expression (request = `{caller, tool, args}`) | Result |
|---|---|
| `request.tool.startsWith("fs_")` | `BoolType(True)` |
| `request.tool.matches("^fs[._](read\|write)_")` | `BoolType(True)` |
| `request.args.path.contains("..")` | `BoolType(True)` |
| `request.tool in ["fs_read_file", "shell_run"]` | `BoolType(True)` |
| `has(request.args.path)` / `has(request.args.nope)` | `True` / `False` |
| `request.args["path"].contains("/")`, `size(request.args) == 2` | `BoolType(True)` (index + size work) |
| `["fs_read_file"].exists(t, t.startsWith("fs_"))` | `BoolType(True)` (macros work) |

Types and failure modes:
- `json_to_cel()` maps `str→StringType`, `bool→BoolType`, `int→IntType`, `dict→MapType`,
  `list→ListType`. Passing a plain `dict` as the activation value fails: `CELEvalError (... with type:
  '<class 'dict'>' does not support field selection)`.
- `BoolType` subclasses `int`: `bool(out)` and `out == True` work, but `isinstance(out, bool)` and
  `out is True` are `False`. Never `if out:` on an int result — test `isinstance(out, celtypes.BoolType)`.
- Missing key/member → `celpy.evaluation.CELEvalError` (wraps `KeyError`, `no such member in mapping:
  'nope'`); syntax error → `celpy.celparser.CELParseError` at `env.compile`. Both are plain
  `Exception`s — catch broadly for fail-closed.
- `matches()` is **partial** (`re.search`): `"fs_read_file".matches("read")` → `True`,
  `matches("^read")` → `False`. Anchor with `^...$` when you mean full match. Compiled programs are
  reusable across requests (verified).

## 6. google-adk 2.15.0 — agents, output_schema, runners

**verified**: imports/signatures + full runner loop against a stub `BaseLlm` (no API key, no network);
real model calls are unverified. Env needed for AI Studio (values read by `google-genai`'s client):
`GOOGLE_API_KEY=<key>` and `GOOGLE_GENAI_USE_VERTEXAI=FALSE` (grep in `google/genai/_api_client.py`
lines 162–172, 872).

```python
import os
from google.adk.agents import LlmAgent
from google.adk.runners import InMemoryRunner
from google.genai import types
from pydantic import BaseModel

class Verdict(BaseModel):
    allowed: bool
    reason: str

judge = LlmAgent(
    name="judge",
    model=os.environ.get("ADMIT_MODEL", "gemini-2.5-flash"),   # plain string; resolved lazily
    instruction="Return a JSON verdict.",
    output_schema=Verdict,        # dict | pydantic model | genai Schema; forces JSON output
    tools=[],                     # combining output_schema + tools constructs fine in 2.15
)

async def ask(agent, text: str) -> str:
    runner = InMemoryRunner(agent=agent, app_name="admit")
    sess = await runner.session_service.create_session(app_name="admit", user_id="u1", session_id="s1")
    out = []
    async for event in runner.run_async(user_id="u1", session_id=sess.id,
            new_message=types.Content(role="user", parts=[types.Part(text=text)])):
        if event.is_final_response():
            out.append("".join(p.text or "" for p in (event.content.parts or [])))
    return "".join(out)
```

- `runner.run(...)` is the sync generator twin of `run_async(...)`; both take keyword-only
  `user_id`, `session_id`, `new_message`. `agent.model` stays the **string** you passed
  (`judge.model == "gemini-2.5-flash"`); the resolved model object is internal.

Looping with early exit (**verified**: sub-agent ran once with `max_iterations=5`):

```python
from google.adk.agents import BaseAgent, LoopAgent
from google.adk.events import Event, EventActions
from google.adk.tools import exit_loop          # a tool you hand to the LLM; it sets escalate

class EscalateAfterFirst(BaseAgent):            # any sub-agent may bail out early
    name: str = "esc"
    async def _run_async_impl(self, ctx):
        yield Event(author=self.name, invocation_id=ctx.invocation_id,
                    actions=EventActions(escalate=True),
                    content=types.Content(role="model", parts=[types.Part(text="done")]))

loop = LoopAgent(name="loop", sub_agents=[EscalateAfterFirst(), reviewer], max_iterations=5)
```

`LoopAgent` stops when a sub-agent event has `actions.escalate` or `max_iterations` is hit
(0 runs the sub-agents zero times). `SequentialAgent(name=..., sub_agents=[...])` runs children in
order. Both emit `DeprecationWarning: ... deprecated in favor of Workflow` in 2.15 —
`google.adk.workflow.Workflow` exists (with `BaseNode`, `FunctionNode`, `JoinNode`, `Edge`), but
`LoopAgent` still works and is the shortest path today.

## 7. Gemini CLI 0.70.0 settings

Sources: `$(npm root -g)/@google/gemini-cli/bundle/docs/` (`reference/configuration.md`, `tools/mcp-server.md`,
`cli/trusted-folders.md`, `reference/tools.md`) plus the shipped bundle JS.

Project-level `.gemini/settings.json` (**verified**: `gemini mcp list` recognised the entry as
`admit: http://127.0.0.1:8765/mcp (http)`):

```json
{
  "mcpServers": {
    "admit": {
      "httpUrl": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer ${ADMIT_TOKEN}" },
      "timeout": 300000, "trust": true
    }
  },
  "tools": { "core": [] },
  "security": { "folderTrust": { "enabled": false } }
}
```

- `httpUrl` = streamable HTTP (`url` = SSE); precedence `httpUrl` > `url` > `command`; `headers`
  apply to `url`/`httpUrl`. `"trust": true` bypasses per-call confirmation (default `false`).
- `${VAR}` / `$VAR` / `%VAR%` expansion **does** apply to header values (verified in
  `createTransportRequestInit` → `expandEnvVars`, bundle line ~395464), so keep the token out of the
  file: `"Authorization": "Bearer ${ADMIT_TOKEN}"`.
- `"tools": {"core": []}` removes every built-in tool: registration goes through
  `maybeRegister(...)` and `if (coreTools) { ... coreTools.some(...) }` — in JS an empty array is
  truthy, so every `.some()` is false and nothing built-in registers. MCP tools are registered
  outside that gate, so only Admit's tools remain. (`tools.core` takes tool names like
  `read_file` or class names like `ReadFileTool`, plus `ShellTool(ls)`-style command allowlists.)
- Deprecated but still parsed: `tools.exclude` (blocklist), `tools.allowed` (auto-approve),
  `tools.confirmationRequired`; `excludeTools`/`includeTools` inside an `mcpServers` entry filter that
  server's tools only.
- Built-in tool names (bundled `reference/tools.md`): `run_shell_command`, `glob`, `grep_search`,
  `list_directory`, `read_file`, `read_many_files`, `replace`, `write_file`, `ask_user`, `write_todos`,
  `list_mcp_resources`, `read_mcp_resource`, `activate_skill`, `get_internal_docs`, `enter_plan_mode`,
  `exit_plan_mode`, `google_web_search`, `web_fetch`, `update_topic`, `list_background_processes`,
  `read_background_output`, `tracker_*`, `complete_task`.
- MCP tool FQN: `` `mcp_${serverName}${"_"}${serverToolName}` `` — so Admit's `fs.read_file` becomes
  **`mcp_admit_fs.read_file`**. Sanitiser `generateValidName` allows `[a-zA-Z0-9_\-.:]` (dots kept!),
  prefixes `mcp_`, underscores anything else, and truncates names over 64 chars
  (`first30 + "..." + last30`). Avoid `_` in the server alias: the policy engine splits the FQN on the
  first `_` after `mcp_`.
- Folder trust: project settings are **not** loaded in an untrusted folder. Verified: `gemini mcp list`
  printed `Warning: MCP servers are configured but disabled because this folder is untrusted...` and
  `○ admit: http://127.0.0.1:8765/mcp (http) - Disabled`, even though that `settings.json` itself said
  `security.folderTrust.enabled: false`. Fixes: put that same block in `~/.gemini/settings.json`, or run
  with `--skip-trust` / `GEMINI_CLI_TRUST_WORKSPACE=true` (choice cached in `~/.gemini/trustedFolders.json`;
  `GEMINI_CLI_TRUSTED_FOLDERS_PATH` relocates it).
- Auth: `GEMINI_API_KEY` (AI Studio) alone is enough; `GOOGLE_API_KEY` + Vertex flags for Vertex; OAuth
  otherwise. Settings equivalents: `security.auth.selectedType` (`"gemini-api-key"`,
  `"oauth-personal"`, `"compute-default-credentials"`), `.enforcedType`, `.useExternal`. Without any of
  these the CLI refuses to start, even for `gemini mcp list`.
- `gemini mcp list` is **not** offline: with a dummy key it ran model routing and failed with
  `API key not valid`. `unverified`: a real tool-call round trip (no key), i.e. the bearer header
  reaching Admit from Gemini CLI.

## 8. pytest-bdd 9.0.1 — feature + steps + `bdd_features_base_dir`

**verified** (3 passed; then removing the ini option → `FileNotFoundError: ...\tests\policy.feature`).
Repo `pyproject.toml` already has `bdd_features_base_dir = "features/"` and `testpaths = ["tests"]`.

`pytest.ini` (repo `pyproject.toml` already carries both keys):

```ini
[pytest]
testpaths = tests
bdd_features_base_dir = features/
```

`features/policy.feature`:

```gherkin
Feature: CEL policy decisions
  Scenario: denied shell command
    Given a policy that denies tool "shell_run"
    When the agent calls tool "shell_run" with command "rm -rf /"
    Then the decision is deny and the rule is "deny-shell"

  Scenario Outline: allowlisted tools
    Given a policy that denies tool "shell_run"
    When the agent calls tool "<tool>" with command "ls"
    Then the decision is <decision>

    Examples:
      | tool      | decision |
      | fs_read   | allow    |
      | shell_run | deny     |
```

`tests/test_policy.py`:

```python
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

scenarios("policy.feature")          # resolved against bdd_features_base_dir

@given(parsers.parse('a policy that denies tool "{tool}"'), target_fixture="state")
def deny_policy(tool):
    return {"policies": [(tool, "deny-shell")], "decision": None, "rule": None}

@when(parsers.parse('the agent calls tool "{tool}" with command "{cmd}"'))
def call_tool(state, tool, cmd): ...

@then(parsers.parse('the decision is deny and the rule is "{rule}"'))
def is_deny(state, rule): ...

@then(parsers.re(r"^the decision is (?P<decision>allow|deny)$"))   # anchored on purpose
def is_decision(state, decision): ...
```

Gotcha (hit it live): a generic `@then(parsers.parse("the decision is {decision}"))` also matched
`the decision is deny and the rule is "deny-shell"`, swallowing the rest into `{decision}` and failing
with `'deny' == 'deny and the rule is "deny-shell"'`. Fix: anchor the loose step
(`parsers.re(r"^...$")`) or restrict the value (`(?P<decision>allow|deny)`). `scenarios()` binds
`Scenario` and `Scenario Outline`/`Examples` alike; `target_fixture=` on a `given` is the idiomatic
way to share state.

### Not verified (and why)

- Any real Gemini/ADK model call — no API key. ADK snippets ran against a stub `BaseLlm` subclass:
  runner/session/event plumbing is real, the network path is not.
- Gemini CLI → Admit live MCP handshake and tool invocation (no key: the CLI refuses to start, and
  `gemini mcp list` needs auth). Config parsing, trust gating, FQN construction and header env
  expansion were verified from CLI output and shipped code respectively.
- `tools.core: []` end-to-end in a running Gemini session — verified by code path (empty array is
  truthy in JS; all built-ins go through `maybeRegister`) rather than by observing a tool list.

## 9. Antigravity CLI (`agy`) — harness for the demo

Sources: Google's own docs shipped with the Antigravity app
(`~/.gemini/antigravity/builtin/skills/agy-customizations/docs/{hooks,mcp_servers,json_configs}.md`,
`.../antigravity_guide/references/{cli,sdk}.md`) and the public docs at
`https://antigravity.google/docs/{cli/reference,cli/headless,install,settings,models,permissions}`
(read 2026-11-21). Everything above "Observed 2026-11-21" at the end of this section comes from
the docs and is unverified; that subsection lists what was actually run.

### Install, auth, headless

| Item | Value |
|---|---|
| Install (PowerShell) | `irm https://antigravity.google/cli/install.ps1 \| iex` → `%LOCALAPPDATA%\agy\bin\agy.exe`; check `agy --version` |
| Auth (use this) | run `agy` once, choose **Google OAuth**; session cached in Windows Credential Manager. Headless runs reuse it; with no cached session `agy -p` exits with `authentication required` |
| Auth (do NOT use for the demo) | `"modelProvider": "gemini"` in `~/.gemini/antigravity-cli/settings.json` + `GEMINI_API_KEY` switches to AI Studio quota, i.e. back to 429s. `agy` ignores `GOOGLE_API_KEY` and `.env` |
| Headless | `agy -p "<prompt>"` (`--print`/`--prompt`); `--output-format text\|json\|stream-json`; `--json-schema <schema\|file\|type>`; `--print-timeout 15m` (default none); `--mode default\|accept-edits\|auto\|plan` (`-p` defaults to `auto` since v1.5.7); results on stdout, diagnostics on stderr |
| Unapproved calls in `-p` | soft-denied, run still exits 0 with a notice on stderr |
| Model | `--model <slug or label>`; `agy models` lists slugs (account dependent). Docs example: `gemini-3.6/3.7/3.8-flash-{high,medium}`, `gemini-3.1-pro-high`, `gemini-4-*`; Claude and GPT-OSS by label only. Unknown slug in `-p` → exit 1, no fallback |
| Settings | `~/.gemini/antigravity-cli/settings.json` (global only; no per-project settings documented). `permissions: {allow, ask, deny}` with rules like `command(git)`, `command(regex:...)`, `read_file(...)`, `write_file(src/)`, `mcp(server/*)`; Deny > Ask > Allow. `allowNonWorkspaceAccess` (default false). **No setting disables built-in tools.** |

### Hooks (`hooks.json`) — the enforcement point

- Locations: `<workspace>/.agents/hooks.json` and global `~/.gemini/config/hooks.json`. Hooks in
  `settings.json` are **not** loaded. Same file is honoured by the Antigravity app and IDE.
- Shape: `{"<hook name>": {"enabled": true, "PreToolUse": [{"matcher": "*", "hooks": [{"type":
  "command", "command": "...", "timeout": 30}]}]}}`. `matcher` is a regex on the tool name; `"*"`
  or `""` matches all. Named hooks from several files are **merged and run sequentially**.
- Runs via `cmd /c` on Windows, working directory = the folder containing `hooks.json`, default
  timeout 30 s, synchronous (blocks the agent loop).
- stdin (camelCase): `{"toolCall": {"id", "name", "args"}, "stepIdx", "conversationId",
  "workspacePaths", "transcriptPath", "artifactDirectoryPath", "modelName", "lastUserInput",
  "hookEventName", "cwd"}`. Documented example: `name: "run_command"`, `args: {"CommandLine": "npm test"}`.
  `modelName` is `"auto"` in the doc example: pin `--model`.
- stdout: `{"decision": "allow"|"deny"|"ask"|"force_ask", "reason": "...", "permissionOverrides":
  [...], "overwrite": {...}}`. `allow` skips Antigravity's own prompt. `deny` is a hard block.
  `overwrite` is a shallow merge into args, and the agent is told its args were rewritten.
- Tool names = step type lowercased without `CORTEX_STEP_TYPE_`. Only `run_command` is shown in
  the docs; `view_file`, `write_to_file`, `replace_file_content`, `list_dir`, `grep_search`,
  `find_by_name`, `read_url_content`, `browser_*` are **expected, unconfirmed**.
- **Undocumented (test in M3):** non-zero exit, crash, non-JSON stdout, timeout, command that cannot
  start, and how multiple `PreToolUse` decisions combine.

### MCP (`mcp_config.json`)

`<workspace>/.agents/mcp_config.json` or `~/.gemini/config/mcp_config.json`;
`{"mcpServers": {"admit": {"url": "http://127.0.0.1:8765/mcp"}}}` (`serverUrl` also accepted;
Streamable HTTP only, no legacy SSE). **No `headers` field is documented**, so Admit's bearer token
cannot be sent this way. Workaround if MCP is needed: a stdio bridge (`npx mcp-remote <url>
--header "Authorization: Bearer ..."`) as a `command` entry. Project server names must differ from
global ones.

### M0 tap hook (capture real payloads)

`adapters/antigravity/tap.py` appends each stdin payload to `.admit/tap.jsonl` and prints
`{"decision": "allow"}`. Point a throwaway `.agents/hooks.json` at it in a scratch folder (not
`demo-repo/`), ask `agy -p` to read, write, edit, list and run something, then paste the observed
tool names and arg keys here and fix the mapping table in plan.md section 2.

### Python SDK

`pip install google-antigravity`; `from google.antigravity import Agent, LocalAgentConfig,
CapabilitiesConfig`. Read-only by default; `response.tool_calls` streams typed tool calls. Its auth
path is not documented in the shipped reference, so the plan uses the CLI (`AgyLlm`) instead.

### Observed 2026-11-21 (`agy` 1.5.14, Windows) — verified

- Installed via the official `install.ps1` (SHA-512 checked, adds `%LOCALAPPDATA%\agy\bin` to the user PATH).
  **Already signed in**: `agy` reused the Antigravity desktop app's Google session; no login prompt.
  `agy -p` worked with `GEMINI_API_KEY`/`GOOGLE_API_KEY` removed from the environment.
- `agy models` (this account): `gemini-3.8-flash-{high,medium,low}`, `claude-sonnet-4-6`,
  `claude-opus-4-6-thinking`, `gpt-oss-120b-medium`. No flash-lite, no 3.6/3.7 flash.
- `--output-format stream-json` events: `init` (model, cwd, full tool list, `permission_mode`),
  `step_update` (`step_type: "tool"`, `tool_info: {name, parameters}`), `result` (`status`,
  `response`, `duration_seconds`, `usage`).
- Tool list in `init`: `run_command`, `view_file`, `write_to_file`, `replace_file_content`,
  `multi_replace_file_content`, `sed_file`, `list_dir`, `find_by_name`, `grep_search`,
  `read_url_content`, `search_web`, `call_mcp_tool`, `send_command_input`, `command_status`,
  `notebook_edit`, `browser_*`, subagent/schedule/inbox tools, and others.
- **But `step_update.tool_info.name` uses different names**: `read_file` / `edit_file` /
  `write_file` with `{"Path": ...}`, and `run_command` with `{"CommandLine": ...}`. Which set the
  `PreToolUse` hook receives is still unknown: the M0 tap hook decides it. Map both.
