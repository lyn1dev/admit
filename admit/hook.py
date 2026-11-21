"""``admit hook``: BeforeTool/PreToolUse hook for Antigravity, Gemini CLI, Claude Code.

Reads one harness tool call from stdin, maps it onto the shared policy tool
names, decides via ``POST /check`` to ``admit serve``, and prints harness-
specific output. Fail-closed: any error denies, nothing but JSON is ever
written to stdout, and ``main`` wraps everything in ``except BaseException``.

Startup must stay fast (runs before every tool call): stdlib only, no admit
package imports besides this module.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, TextIO

DEFAULT_URL = "http://127.0.0.1:8765"
HTTP_TIMEOUT = 70.0  # WARN calls are held server-side for up to 60 s
# Exit code for an Antigravity *policy* deny (JSON on stdout). To be confirmed
# by the hook-failure matrix (docs/dev/plan.md section 2). Internal errors use 2.
ANTIGRAVITY_DENY_EXIT = 0
ALLOWED_VERDICTS = ("ALLOW", "WOULD_DENY")

_PATH_KEYS = ("Path", "AbsolutePath", "DirectoryPath", "SearchPath", "TargetFile")

# Value: (policy tool, harness arg key(s) -> policy arg key). A tuple of keys
# means "first present key wins".
ToolSpec = tuple[str, dict[str, Any]]

_AGY_PATH: dict[str, Any] = {_PATH_KEYS: "path"}
ANTIGRAVITY_TOOL_MAP: dict[str, ToolSpec] = {
    "run_command": ("shell.run", {("CommandLine",): "command"}),
    "read_file": ("fs.read_text_file", _AGY_PATH),
    "view_file": ("fs.read_text_file", _AGY_PATH),
    "write_file": ("fs.write_file", _AGY_PATH),
    "write_to_file": ("fs.write_file", _AGY_PATH),
    "edit_file": ("fs.edit_file", _AGY_PATH),
    "replace_file_content": ("fs.edit_file", _AGY_PATH),
    "multi_replace_file_content": ("fs.edit_file", _AGY_PATH),
    "sed_file": ("fs.edit_file", _AGY_PATH),
    "list_dir": ("fs.list_directory", _AGY_PATH),
    "grep_search": ("fs.search_files", _AGY_PATH),
    "find_by_name": ("fs.search_files", _AGY_PATH),
    "read_url_content": ("net.fetch", {("Url", "url"): "url"}),
    "search_web": ("net.search", {("query", "Query"): "query"}),
}

_GEM_PATH: dict[str, Any] = {("file_path", "path"): "path"}
GEMINI_TOOL_MAP: dict[str, ToolSpec] = {
    "run_shell_command": ("shell.run", {("command",): "command"}),
    "read_file": ("fs.read_text_file", _GEM_PATH),
    "read_many_files": ("fs.read_text_file", {("paths", "file_path"): "path"}),
    "write_file": ("fs.write_file", _GEM_PATH),
    "replace": ("fs.edit_file", _GEM_PATH),
    "list_directory": ("fs.list_directory", {("dir_path", "path"): "path"}),
    "glob": ("fs.search_files", {("dir_path", "path"): "path"}),
    "grep_search": ("fs.search_files", {("dir_path", "path"): "path"}),
    "web_fetch": ("net.fetch", {("url", "prompt"): "url"}),
    "google_web_search": ("net.search", {("query",): "query"}),
}

_CC_PATH: dict[str, Any] = {("file_path", "path", "notebook_path"): "path"}
_CC_DIR: dict[str, Any] = {("path",): "path"}
CLAUDE_TOOL_MAP: dict[str, ToolSpec] = {
    "Bash": ("shell.run", {("command",): "command"}),
    "Read": ("fs.read_text_file", _CC_PATH),
    "Write": ("fs.write_file", _CC_PATH),
    "Edit": ("fs.edit_file", _CC_PATH),
    "MultiEdit": ("fs.edit_file", _CC_PATH),
    "NotebookEdit": ("fs.edit_file", _CC_PATH),
    "Glob": ("fs.search_files", _CC_DIR),
    "Grep": ("fs.search_files", _CC_DIR),
    "LS": ("fs.list_directory", _CC_DIR),
    "WebFetch": ("net.fetch", {("url",): "url"}),
    "WebSearch": ("net.search", {("query",): "query"}),
}

TOOL_MAPS: dict[str, dict[str, ToolSpec]] = {
    "antigravity": ANTIGRAVITY_TOOL_MAP,
    "gemini": GEMINI_TOOL_MAP,
    "claude": CLAUDE_TOOL_MAP,
}

# Tools the gateway already checked (Admit's own MCP server): skip /check.
PASSTHROUGH_PREFIXES = ("mcp_admit_", "mcp__admit__")


class HookError(Exception):
    """Internal failure: becomes a deny (exit 2)."""


_DEFAULTS_TO_WORKSPACE = frozenset({"fs.list_directory", "fs.search_files"})


def _workspace(payload: dict[str, Any]) -> str:
    paths = payload.get("workspacePaths")
    if isinstance(paths, list) and paths and isinstance(paths[0], str) and paths[0]:
        return paths[0]
    cwd = payload.get("cwd")
    return cwd if isinstance(cwd, str) else ""


def _norm(p: str) -> str:
    return os.path.normcase(os.path.realpath(p))


def normalise_path(path: str, workspace: str) -> str:
    """Absolute path inside the workspace -> workspace-relative, forward slashes.

    Anything else (relative input, outside the workspace) is returned unchanged.
    """
    if not workspace or not os.path.isabs(path):
        return path
    try:
        ws = _norm(workspace)
        target = _norm(path)
        if os.path.commonpath([ws, target]) != ws:
            return path
        rel = os.path.relpath(target, ws)
    except ValueError:  # different drives
        return path
    if rel == ".":
        return "."
    # Re-derive from the original path's tail so case is preserved.
    parts = rel.replace("\\", "/")
    orig = path.replace("\\", "/")
    if len(orig) >= len(parts) and orig[-len(parts) :].lower() == parts.lower():
        return orig[-len(parts) :]
    return parts


def _first(args: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in args and args[k] not in (None, ""):
            return args[k]
    return None


def map_call(harness: str, payload: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Map one harness tool call onto ``[{"tool", "args"}, ...]`` policy calls.

    Returns None for calls that must skip /check (Admit's own MCP tools).
    One built-in call can become several requests (read_many_files).
    Unknown tools map to ``builtin.<name>`` with raw args (default-deny).
    """
    tool_map = TOOL_MAPS.get(harness)
    if tool_map is None:
        raise HookError(f"unknown harness {harness!r}")
    if harness == "antigravity":
        call = payload.get("toolCall")
        if not isinstance(call, dict) or not isinstance(call.get("name"), str):
            raise HookError("payload has no toolCall.name")
        name, args = call["name"], call.get("args")
    else:
        name = payload.get("tool_name")
        args = payload.get("tool_input")
        if not isinstance(name, str) or not name:
            raise HookError("payload has no tool_name")
    if not isinstance(args, dict):
        args = {}

    if name.startswith(PASSTHROUGH_PREFIXES):
        return None
    spec = tool_map.get(name)
    if spec is None:
        return [{"tool": f"builtin.{name}", "args": args}]

    tool, keymap = spec
    ws = _workspace(payload)
    values: dict[str, list[Any]] = {}
    for keys, out_key in keymap.items():
        v = _first(args, keys)
        if v is None:
            continue
        values[out_key] = v if isinstance(v, list) else [v]
    if "path" not in values and tool in _DEFAULTS_TO_WORKSPACE:
        # glob / grep_search / list_dir without a directory search the workspace
        # (the harness default), so say so instead of sending no path at all.
        values["path"] = ["."]
    if not values:
        # Mapped tool but no usable arg (e.g. list_dir with no path): the
        # server still decides, with empty args.
        return [{"tool": tool, "args": {}}]

    n = max(len(v) for v in values.values())
    requests = []
    for i in range(n):
        out: dict[str, Any] = {}
        for k, vs in values.items():
            v = vs[i] if i < len(vs) else vs[0]
            if k == "path" and isinstance(v, str):
                v = normalise_path(v, ws)
            out[k] = v
        requests.append({"tool": tool, "args": out})
    return requests


def find_token(cwd: str | None = None) -> str:
    """``ADMIT_TOKEN``, else ``.admit/hook-token`` in the workspace, or in the
    process directory and up to 3 parents."""
    env = os.environ.get("ADMIT_TOKEN", "").strip()
    if env:
        return env
    dirs: list[str] = []
    if cwd:
        dirs.append(cwd)
    here = os.getcwd()
    for _ in range(4):
        dirs.append(here)
        parent = os.path.dirname(here)
        if parent == here:
            break
        here = parent
    for d in dirs:
        f = os.path.join(d, ".admit", "hook-token")
        try:
            with open(f, encoding="utf-8") as fh:
                tok = fh.read().strip()
        except OSError:
            continue
        if tok:
            return tok
    raise HookError(
        "no Admit token: set ADMIT_TOKEN or start `uv run admit serve` (writes .admit/hook-token)"
    )


def post_check(url: str, token: str, body: dict[str, Any]) -> dict[str, Any]:
    """POST one request to ``/check``; return the parsed JSON object."""
    req = urllib.request.Request(
        url.rstrip("/") + "/check",
        data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # noqa: S310
            status = resp.status
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raise HookError(f"Admit returned HTTP {e.code} (check the hook token)") from e
    except urllib.error.URLError as e:
        raise HookError(
            f"Admit is not running at {url} — start `uv run admit serve` ({e.reason})"
        ) from e
    except TimeoutError as e:
        raise HookError("Admit timed out waiting for a decision") from e
    except OSError as e:
        raise HookError(f"Admit is not running at {url} — start `uv run admit serve` ({e})") from e
    if status != 200:
        raise HookError(f"Admit returned HTTP {status}")
    try:
        data = json.loads(raw)
    except ValueError as e:
        raise HookError("Admit returned a non-JSON response") from e
    if not isinstance(data, dict) or not isinstance(data.get("allowed"), bool):
        raise HookError("Admit response has no 'allowed' field")
    return data


def _verdict_allowed(data: dict[str, Any]) -> bool:
    return bool(data["allowed"]) and data.get("decision") in ALLOWED_VERDICTS


def decide(
    harness: str, payload: dict[str, Any], url: str, token_cwd: str | None
) -> tuple[bool, dict[str, Any]]:
    """Return ``(allowed, info)``; info has policy/reason/hint of the deciding result."""
    requests = map_call(harness, payload)
    if requests is None:
        return True, {"policy": "admit-gateway", "reason": "already checked by the Admit gateway"}
    token = find_token(token_cwd)
    model = payload.get("modelName") if harness == "antigravity" else payload.get("model")
    if harness == "antigravity":
        model = f"antigravity/{model}" if isinstance(model, str) and model else "antigravity/auto"
    elif not isinstance(model, str):
        model = ""
    last: dict[str, Any] = {}
    for r in requests:
        data = post_check(url, token, {"tool": r["tool"], "args": r["args"], "model": model})
        if not _verdict_allowed(data):
            return False, data
        last = data
    return True, last


def render_allow(harness: str, info: dict[str, Any]) -> tuple[str, int]:
    if harness == "antigravity":
        policy = info.get("policy") or "default"
        return json.dumps({"decision": "allow", "reason": f"admit: {policy}"}), 0
    return "", 0


def render_deny(harness: str, info: dict[str, Any], *, internal: bool = False) -> tuple[str, int]:
    """Return ``(text, exit_code)``; text goes to stdout for antigravity, stderr otherwise."""
    reason = info.get("reason") or "denied"
    policy = info.get("policy") or "default-deny"
    hint = info.get("hint") or ""
    msg = f"Admit blocked this: {reason} (policy {policy}). {hint}".strip()
    if harness == "antigravity":
        code = 2 if internal else ANTIGRAVITY_DENY_EXIT
        return json.dumps({"decision": "deny", "reason": msg}), code
    if harness == "gemini" and not internal:
        # Gemini CLI's documented, preferred block: exit 0 + {"decision": "deny"}; the
        # reason goes to the agent as a tool error. Internal errors still exit 2, the only
        # non-zero code Gemini CLI treats as a block (any other code fails open).
        return json.dumps({"decision": "deny", "reason": msg}), 0
    return msg, 2


def main(harness: str, stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    """Run the hook; returns the exit code. Never raises, never fails open."""
    out = stdout if stdout is not None else sys.stdout
    inp = stdin if stdin is not None else sys.stdin
    stderr_text = ""
    try:
        try:
            payload = json.loads(inp.read())
            if not isinstance(payload, dict):
                raise HookError("stdin is not a JSON object")
            cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
            url = os.environ.get("ADMIT_URL", "").strip() or DEFAULT_URL
            allowed, info = decide(harness, payload, url, _workspace(payload) or cwd)
            if allowed:
                text, code = render_allow(harness, info)
            else:
                text, code = render_deny(harness, info)
        except HookError as e:
            text, code = render_deny(harness, {"reason": str(e), "policy": "hook"}, internal=True)
        except BaseException as e:  # fail closed, even on KeyboardInterrupt/SystemExit
            text, code = render_deny(
                harness,
                {"reason": f"hook error: {type(e).__name__}: {e}", "policy": "hook"},
                internal=True,
            )
    except BaseException:  # pragma: no cover - last resort
        text = json.dumps({"decision": "deny", "reason": "Admit hook crashed"})
        code = 2
    if harness in ("antigravity", "gemini") and not (harness == "gemini" and code == 2):
        if text:
            out.write(text + "\n")
            out.flush()
    else:
        stderr_text = text
        sys.stderr.write(stderr_text + "\n")
        sys.stderr.flush()
    return code


if __name__ == "__main__":
    # Usage: python -m admit.hook antigravity < payload.json
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "antigravity"))
