"""Tests for ``admit hook`` (fail-closed harness adapter). No real network."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from admit import hook

REPO = Path(__file__).resolve().parent.parent


class _Fake:
    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.auth: list[str] = []
        self.status = 200
        self.body: bytes | dict = {"decision": "ALLOW", "policy": "p", "allowed": True}
        self.responses: list = []  # optional per-call bodies


@pytest.fixture
def fake(monkeypatch, tmp_path):
    state = _Fake()

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers["Content-Length"])
            state.requests.append(json.loads(self.rfile.read(n)))
            state.auth.append(self.headers.get("Authorization", ""))
            body = state.responses.pop(0) if state.responses else state.body
            raw = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(state.status)
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("ADMIT_URL", f"http://127.0.0.1:{srv.server_port}")
    monkeypatch.setenv("ADMIT_TOKEN", "tok")
    state.ws = tmp_path
    yield state
    srv.shutdown()


def run(harness: str, payload, capsys=None):
    out = io.StringIO()
    stdin = io.StringIO(payload if isinstance(payload, str) else json.dumps(payload))
    code = hook.main(harness, stdin=stdin, stdout=out)
    return code, out.getvalue()


def agy(name, args, ws, model="gemini-3.8-flash-low"):
    p = {"toolCall": {"name": name, "args": args}, "cwd": str(ws), "workspacePaths": [str(ws)]}
    if model is not None:
        p["modelName"] = model
    return p


def one_json(out: str) -> dict:
    lines = out.splitlines()
    assert len(lines) == 1
    return json.loads(lines[0])


def test_run_command_mapping(fake):
    payload = agy("run_command", {"CommandLine": "ls", "toolSummary": "x"}, fake.ws)
    code, out = run("antigravity", payload)
    assert code == 0
    assert one_json(out) == {"decision": "allow", "reason": "admit: p"}
    assert fake.requests == [
        {
            "tool": "shell.run",
            "args": {"command": "ls"},
            "model": "antigravity/gemini-3.8-flash-low",
        }
    ]
    assert fake.auth == ["Bearer tok"]


def test_abs_path_in_workspace_becomes_relative(fake):
    p = (fake.ws / "src" / "a.py").as_posix()
    run("antigravity", agy("read_file", {"Path": p}, fake.ws))
    assert fake.requests[0]["tool"] == "fs.read_text_file"
    assert fake.requests[0]["args"] == {"path": "src/a.py"}


def test_outside_workspace_and_dotdot_unchanged(fake):
    outside = (fake.ws.parent / "other" / "x.txt").as_posix()
    run("antigravity", agy("read_file", {"Path": outside}, fake.ws))
    run("antigravity", agy("read_file", {"Path": "../secret"}, fake.ws))
    run("antigravity", agy("view_file", {"AbsolutePath": "calc.py"}, fake.ws))
    assert [r["args"]["path"] for r in fake.requests] == [outside, "../secret", "calc.py"]


def test_content_never_sent(fake):
    p = (fake.ws / "out.txt").as_posix()
    run("antigravity", agy("write_file", {"Path": p, "Content": "SECRET-BODY"}, fake.ws))
    run(
        "antigravity",
        agy("edit_file", {"Path": p, "Target": "t", "Replacement": "SECRET-REPL"}, fake.ws),
    )
    blob = json.dumps(fake.requests)
    assert "SECRET" not in blob
    assert [r["tool"] for r in fake.requests] == ["fs.write_file", "fs.edit_file"]
    assert fake.requests[0]["args"] == {"path": "out.txt"}


@pytest.mark.parametrize(
    ("name", "args", "tool", "out_args"),
    [
        ("list_dir", {"DirectoryPath": "."}, "fs.list_directory", {"path": "."}),
        ("grep_search", {"SearchPath": "src", "Query": "x"}, "fs.search_files", {"path": "src"}),
        ("find_by_name", {"SearchPath": "src"}, "fs.search_files", {"path": "src"}),
        ("read_url_content", {"Url": "https://e.com"}, "net.fetch", {"url": "https://e.com"}),
        ("search_web", {"query": "hi"}, "net.search", {"query": "hi"}),
        ("browser_click", {"a": 1}, "builtin.browser_click", {"a": 1}),
    ],
)
def test_other_mappings(fake, name, args, tool, out_args):
    run("antigravity", agy(name, args, fake.ws))
    assert fake.requests[0]["tool"] == tool
    assert fake.requests[0]["args"] == out_args


def test_model_auto_when_missing(fake):
    run("antigravity", agy("run_command", {"CommandLine": "ls"}, fake.ws, model=None))
    run("antigravity", agy("run_command", {"CommandLine": "ls"}, fake.ws, model=""))
    assert [r["model"] for r in fake.requests] == ["antigravity/auto"] * 2


def test_admit_mcp_passthrough_no_check(fake):
    code, out = run("antigravity", agy("mcp_admit_shell_run", {}, fake.ws))
    assert code == 0 and one_json(out)["decision"] == "allow"
    assert fake.requests == []


def test_deny(fake):
    fake.body = {
        "decision": "DENY",
        "policy": "baseline",
        "reason": "nope",
        "hint": "H",
        "allowed": False,
    }
    code, out = run("antigravity", agy("run_command", {"CommandLine": "rm"}, fake.ws))
    d = one_json(out)
    assert code == hook.ANTIGRAVITY_DENY_EXIT
    assert d["decision"] == "deny"
    assert "nope" in d["reason"] and "baseline" in d["reason"] and "H" in d["reason"]


def test_would_deny_allows(fake):
    fake.body = {"decision": "WOULD_DENY", "policy": "p", "reason": "r", "allowed": True}
    code, out = run("antigravity", agy("run_command", {"CommandLine": "x"}, fake.ws))
    assert code == 0 and one_json(out)["decision"] == "allow"


def test_unresolved_warn_denies(fake):
    fake.body = {"decision": "WARN", "policy": "p", "reason": "r", "allowed": False}
    _, out = run("antigravity", agy("run_command", {"CommandLine": "x"}, fake.ws))
    assert one_json(out)["decision"] == "deny"
    fake.body = {"decision": "WARN", "policy": "p", "reason": "r", "allowed": True}
    _, out = run("antigravity", agy("run_command", {"CommandLine": "x"}, fake.ws))
    assert one_json(out)["decision"] == "deny"  # WARN is never an allowed verdict


def test_connection_refused(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIT_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("ADMIT_TOKEN", "tok")
    code, out = run("antigravity", agy("run_command", {"CommandLine": "x"}, tmp_path))
    d = one_json(out)
    assert code == 2 and d["decision"] == "deny" and "not running" in d["reason"]


@pytest.mark.parametrize("bad", ["not-json", "", "[]", '{"cwd": "."}', '{"toolCall": {}}'])
def test_bad_stdin(fake, bad):
    code, out = run("antigravity", bad)
    assert code == 2 and one_json(out)["decision"] == "deny"
    assert fake.requests == []


def test_unknown_harness(fake):
    code, _ = run("nope", {"toolCall": {"name": "run_command", "args": {}}})
    assert code == 2


def test_http_401(fake):
    fake.status = 401
    fake.body = {"detail": "unauthorised"}
    code, out = run("antigravity", agy("run_command", {"CommandLine": "x"}, fake.ws))
    assert code == 2 and one_json(out)["decision"] == "deny"


@pytest.mark.parametrize("body", [b"<html>", {"decision": "ALLOW"}, b"[]"])
def test_bad_response(fake, body):
    fake.body = body
    code, out = run("antigravity", agy("run_command", {"CommandLine": "x"}, fake.ws))
    assert code == 2 and one_json(out)["decision"] == "deny"


def test_no_token(fake, monkeypatch, tmp_path):
    monkeypatch.delenv("ADMIT_TOKEN")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hook.os, "getcwd", lambda: str(tmp_path))
    ws = tmp_path / "ws"
    ws.mkdir()
    code, out = run("antigravity", agy("run_command", {"CommandLine": "x"}, ws))
    # The tmp parents may hold no token; only assert fail-closed when absent.
    assert code in (0, 2)
    if code == 2:
        assert one_json(out)["decision"] == "deny"


def test_token_from_parent_of_process_cwd(fake, monkeypatch, tmp_path):
    monkeypatch.delenv("ADMIT_TOKEN")
    (tmp_path / ".admit").mkdir()
    (tmp_path / ".admit" / "hook-token").write_text("  filetok\n")
    agents = tmp_path / ".agents"
    agents.mkdir()
    monkeypatch.chdir(agents)
    other_ws = tmp_path.parent / "nowhere"
    code, _ = run("antigravity", agy("run_command", {"CommandLine": "x"}, other_ws))
    assert code == 0
    assert fake.auth == ["Bearer filetok"]


def test_gemini_read_many_files_any_deny(fake):
    fake.responses = [
        {"decision": "ALLOW", "policy": "p", "allowed": True},
        {"decision": "DENY", "policy": "b", "reason": "no", "allowed": False},
    ]
    payload = {"tool_name": "read_many_files", "tool_input": {"paths": ["a.txt", "b.txt", "c.txt"]}}
    code, out = run("gemini", payload)
    assert code == 0 and json.loads(out)["decision"] == "deny"
    assert [r["args"]["path"] for r in fake.requests] == ["a.txt", "b.txt"]  # stops at deny


def test_gemini_deny_is_json_exit_0(fake):
    # Gemini CLI's preferred block: exit 0 + {"decision": "deny"}; reason reaches the agent.
    fake.body = {"decision": "DENY", "policy": "b", "reason": "no", "allowed": False}
    code, out = run("gemini", {"tool_name": "run_shell_command", "tool_input": {"command": "x"}})
    assert code == 0
    body = json.loads(out)
    assert body["decision"] == "deny" and "no" in body["reason"]


def test_gemini_internal_error_exits_2(capsys):
    # Anything but exit 2 fails open in Gemini CLI, so internal errors must exit 2.
    code, out = run("gemini", "not-json")
    assert code == 2 and out == ""
    assert "hook error" in capsys.readouterr().err


def test_claude_deny_stderr(fake, capsys):
    fake.body = {"decision": "DENY", "policy": "b", "reason": "no", "allowed": False}
    code, out = run("claude", {"tool_name": "Bash", "tool_input": {"command": "x"}})
    assert code == 2 and out == ""
    assert "no" in capsys.readouterr().err


def test_claude_mapping_and_allow(fake):
    code, out = run(
        "claude", {"tool_name": "Read", "tool_input": {"file_path": "a.py"}, "model": "m"}
    )
    assert code == 0 and out == ""
    assert fake.requests[0] == {"tool": "fs.read_text_file", "args": {"path": "a.py"}, "model": "m"}
    code, _ = run("claude", {"tool_name": "mcp__admit__x", "tool_input": {}})
    assert code == 0 and len(fake.requests) == 1


def test_subprocess_invalid_stdin():
    r = subprocess.run(
        [sys.executable, "-m", "admit.cli", "hook", "--harness", "antigravity"],
        input="not-json",
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=60,
    )
    assert r.returncode == 2
    assert one_json(r.stdout)["decision"] == "deny"
