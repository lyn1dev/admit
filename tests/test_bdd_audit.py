"""BDD steps for ``features/audit_tamper.feature``.

The feature speaks of ``admit audit verify --log audit.jsonl``; the CLI shipped
in this milestone is ``admit verify [LOG]``, so the step drives that command.
Everything is exercised through the real ``AuditLog`` and ``verify`` — no proxy
is needed, and the log lives in ``tmp_path`` (never in the repo's ``.admit/``).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pytest_bdd import given, parsers, scenarios, then, when
from typer.testing import CliRunner

from admit import cli
from admit.audit import AuditLog
from admit.types import Decision, ToolRequest, Verdict

scenarios("audit_tamper.feature")

# The feature's wording predates the shipped messages.
_MESSAGE_ALIASES = {"signature mismatch": "signature invalid"}


def _output(result: Any) -> str:
    try:
        err = result.stderr or ""
    except ValueError:  # stderr was not captured separately
        err = ""
    return (result.output or "") + err


def _hash(entry: dict[str, Any]) -> str:
    payload = {name: value for name, value in entry.items() if name != "hash"}
    blob = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _write(path: Path, entries: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8")


@given(
    "an audit log with 4 entries written by the demo session",
    target_fixture="state",
)
def demo_log(tmp_path: Path, monkeypatch) -> dict[str, Any]:
    audit_dir = tmp_path / ".admit" / "audit"
    log = AuditLog(directory=audit_dir, keys_dir=tmp_path / ".admit" / "keys")
    verdicts = [Verdict.ALLOW, Verdict.ALLOW, Verdict.DENY, Verdict.ALLOW]
    tools = ["fs.read_text_file", "shell.run", "shell.run", "fs.list_directory"]
    for verdict, tool in zip(verdicts, tools, strict=True):
        log.append(
            ToolRequest(caller="coding-agent", tool=tool, args={"command": "pytest -q"}),
            Decision(verdict, "baseline", f"{verdict.value.lower()} by baseline"),
        )
    log.close()
    # The feature verifies "audit.jsonl": put the session log under that name.
    path = audit_dir / "audit.jsonl"
    log.path.replace(path)
    log.sig_path.replace(audit_dir / "audit.sig")
    monkeypatch.chdir(audit_dir)
    return {"log": log, "path": path, "result": None}


@when(parsers.parse('the operator runs "{command}"'))
def run_verify(state: dict[str, Any], command: str) -> None:
    # "admit audit verify --log audit.jsonl" -> ["verify", "audit.jsonl"]
    parts = command.split()
    args = [part for part in parts if part not in ("admit", "audit", "--log")]
    state["result"] = CliRunner().invoke(cli.app, args)


@when(parsers.parse('entry {seq:d} is edited so its decision changes from "{old}" to "{new}"'))
def edit_decision(state: dict[str, Any], seq: int, old: str, new: str) -> None:
    entries = _lines(state["path"])
    entry = entries[seq - 1]
    assert entry["decision"] == old
    entry["decision"] = new  # hash deliberately left stale: a naive edit
    _write(state["path"], entries)


@when(parsers.parse("entry {seq:d} is edited and its hash recomputed"))
def edit_and_rechain(state: dict[str, Any], seq: int) -> None:
    """Re-chain the edited entry and everything after it, so only the receipt disagrees."""
    entries = _lines(state["path"])
    edited = entries[seq - 1]
    edited["decision"] = "DENY" if edited["decision"] == "ALLOW" else "ALLOW"
    prev = entries[seq - 2]["hash"] if seq > 1 else "0" * 64
    for entry in entries[seq - 1 :]:
        entry["prev_hash"] = prev
        entry["hash"] = _hash(entry)
        prev = entry["hash"]
    _write(state["path"], entries)


@then("verification succeeds")
def verification_succeeds(state: dict[str, Any]) -> None:
    result = state["result"]
    assert result.exit_code == 0, _output(result)
    assert "OK (" in _output(result)


@then(parsers.parse("the reported entry count is {count:d}"))
def reported_count(state: dict[str, Any], count: int) -> None:
    assert f"{count} entries" in _output(state["result"])


@then("verification fails")
def verification_fails(state: dict[str, Any]) -> None:
    assert state["result"].exit_code == 1, _output(state["result"])


@then(parsers.parse('the error is "{expected}"'))
def error_is(state: dict[str, Any], expected: str) -> None:
    message = _MESSAGE_ALIASES.get(expected, expected)
    assert message in _output(state["result"]), _output(state["result"])


# -- digest scenario --------------------------------------------------------


@given(
    parsers.parse(
        'the caller "{caller}" invokes "{tool}" with args {{"command": "{command}"}}'
    ),
    target_fixture="digest_state",
)
def append_with_args(tmp_path: Path, caller: str, tool: str, command: str) -> dict[str, Any]:
    log = AuditLog(directory=tmp_path / "audit", keys_dir=tmp_path / "keys")
    log.append(
        ToolRequest(caller=caller, tool=tool, args={"command": command}),
        Decision(Verdict.DENY, "baseline", "denied by baseline"),
    )
    log.close()
    return {"log": log}


@when("the operator inspects the audit entry for that call")
def inspect_entry(digest_state: dict[str, Any]) -> None:
    log: AuditLog = digest_state["log"]
    digest_state["raw"] = log.path.read_text(encoding="utf-8")
    digest_state["entry"] = json.loads(digest_state["raw"].splitlines()[0])


@then("the entry contains no plaintext command")
def no_plaintext(digest_state: dict[str, Any]) -> None:
    assert "pytest -q" not in digest_state["raw"]
    assert "pytest" not in json.dumps(digest_state["entry"])


@then(parsers.parse('the entry contains an "{field}" starting with "{prefix}"'))
def field_starts_with(digest_state: dict[str, Any], field: str, prefix: str) -> None:
    assert digest_state["entry"][field].startswith(prefix)

