"""Audit log: hash chain, signed receipt, no content leak, `admit verify`."""

from __future__ import annotations

import hashlib
import json
import shutil
import threading
import time
from pathlib import Path

from typer.testing import CliRunner

from admit import cli
from admit.audit import GENESIS_HASH, AuditLog, latest_log, verify
from admit.types import AUDIT_FIELDS, Decision, ToolRequest, Verdict

SECRET = "sk_live_DO_NOT_LOG_THIS_9f2c"


# -- helpers ----------------------------------------------------------------


def _request(tool: str = "shell.run", args: dict | None = None, caller: str = "coding-agent"):
    if args is None:
        args = {"command": "pytest -q", "token": SECRET}
    return ToolRequest(caller=caller, tool=tool, args=args)


def _decision(verdict: Verdict = Verdict.ALLOW, policy: str | None = "baseline") -> Decision:
    return Decision(verdict, policy, f"{verdict.value.lower()} by {policy}")


def _new_log(tmp_path: Path, name: str = "audit", keys: str = "keys") -> AuditLog:
    return AuditLog(directory=tmp_path / name, keys_dir=tmp_path / keys)


def _fill(log: AuditLog, n: int = 3) -> list[dict]:
    verdicts = [Verdict.ALLOW, Verdict.DENY, Verdict.WARN, Verdict.WOULD_DENY]
    return [
        log.append(_request(tool=f"shell.run{i}"), _decision(verdicts[i % len(verdicts)]))
        for i in range(n)
    ]


def _lines(path: Path) -> list[str]:
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _hash(entry: dict) -> str:
    """Independent implementation of the entry digest (not the module's helper)."""
    payload = {name: value for name, value in entry.items() if name != "hash"}
    blob = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _copy_log(src: Path, dst_dir: Path) -> Path:
    dst_dir.mkdir(parents=True, exist_ok=True)
    copy = dst_dir / src.name
    shutil.copy2(src, copy)
    shutil.copy2(src.with_suffix(".sig"), copy.with_suffix(".sig"))
    return copy


def _output(result) -> str:  # noqa: ANN001 - click's Result
    try:
        err = result.stderr or ""
    except ValueError:  # stderr was not captured separately
        err = ""
    return (result.output or "") + err


# -- chain and receipt ------------------------------------------------------


def test_three_entries_verify_with_count(tmp_path: Path) -> None:
    log = _new_log(tmp_path)
    entries = _fill(log, 3)
    log.close()

    assert [e["seq"] for e in entries] == [1, 2, 3]
    assert entries[0]["prev_hash"] == GENESIS_HASH
    assert all(tuple(entry) == AUDIT_FIELDS for entry in entries)
    assert entries[1]["prev_hash"] == entries[0]["hash"]
    assert entries[2]["prev_hash"] == entries[1]["hash"]

    ok, message = verify(log.path)
    assert ok, message
    assert message == "OK (3 entries, signature valid)"


def test_entry_hash_covers_the_entry_and_uses_genesis_prev(tmp_path: Path) -> None:
    log = _new_log(tmp_path)
    entry = _fill(log, 1)[0]
    assert entry["hash"] == _hash(entry)
    assert entry["decision"] == "ALLOW"


def test_empty_log_with_genesis_receipt_verifies(tmp_path: Path) -> None:
    log = _new_log(tmp_path)
    log.close()
    assert verify(log.path) == (True, "OK (0 entries, signature valid)")


def test_close_is_idempotent(tmp_path: Path) -> None:
    log = _new_log(tmp_path)
    _fill(log, 1)
    log.close()
    first = log.sig_path.read_bytes()
    log.close()
    second = log.sig_path.read_bytes()

    assert json.loads(first)["last_seq"] == 1
    assert json.loads(second)["last_seq"] == 1
    assert verify(log.path) == (True, "OK (1 entries, signature valid)")


# -- no content leak --------------------------------------------------------


def test_raw_arguments_never_reach_the_log(tmp_path: Path) -> None:
    log = _new_log(tmp_path)
    entry = log.append(_request(args={"command": f"echo {SECRET}"}), _decision())
    log.close()

    raw = log.path.read_text(encoding="utf-8")
    assert SECRET not in raw
    assert "echo" not in raw
    assert entry["args_digest"].startswith("sha256:")
    assert SECRET not in entry["args_digest"]
    same = log.append(_request(args={"command": f"echo {SECRET}"}), _decision())
    other = log.append(_request(args={"command": "echo hello"}), _decision())
    assert same["args_digest"] == entry["args_digest"]  # digest, not a nonce
    assert other["args_digest"] != entry["args_digest"]


# -- tampering --------------------------------------------------------------


def test_edited_field_breaks_the_chain_at_that_entry(tmp_path: Path) -> None:
    log = _new_log(tmp_path)
    _fill(log, 3)
    log.close()

    tampered = _copy_log(log.path, tmp_path / "copy")
    lines = _lines(tampered)
    entry = json.loads(lines[1])
    entry["decision"] = "ALLOW"  # entry 2 said DENY
    lines[1] = json.dumps(entry)
    _write_lines(tampered, lines)

    assert verify(tampered) == (False, "chain broken at entry 2")


def test_deleted_middle_line_breaks_the_chain(tmp_path: Path) -> None:
    log = _new_log(tmp_path)
    _fill(log, 3)
    log.close()

    tampered = _copy_log(log.path, tmp_path / "copy")
    lines = _lines(tampered)
    del lines[1]
    _write_lines(tampered, lines)

    ok, message = verify(tampered)
    assert not ok
    assert message.startswith("chain broken at entry")


def test_unparsable_line_is_reported_by_line_number(tmp_path: Path) -> None:
    log = _new_log(tmp_path)
    _fill(log, 3)
    log.close()

    tampered = _copy_log(log.path, tmp_path / "copy")
    lines = _lines(tampered)
    lines[1] = "{not json"
    _write_lines(tampered, lines)

    assert verify(tampered) == (False, "chain broken at entry 2")


def test_forged_receipt_head_is_a_signature_failure(tmp_path: Path) -> None:
    log = _new_log(tmp_path)
    _fill(log, 3)
    log.close()

    tampered = _copy_log(log.path, tmp_path / "copy")
    sig_path = tampered.with_suffix(".sig")
    receipt = json.loads(sig_path.read_text(encoding="utf-8"))
    receipt["last_hash"] = "f" * 64
    sig_path.write_text(json.dumps(receipt), encoding="utf-8")

    assert verify(tampered) == (False, "signature invalid")


def test_removed_receipt_is_reported(tmp_path: Path) -> None:
    log = _new_log(tmp_path)
    _fill(log, 2)
    log.close()

    copied = _copy_log(log.path, tmp_path / "copy")
    copied.with_suffix(".sig").unlink()

    assert verify(copied) == (False, "no signed receipt")


def test_entries_after_the_signed_head_are_unsigned(tmp_path: Path) -> None:
    log = _new_log(tmp_path)
    entries = _fill(log, 3)
    log.close()
    signed_seq = json.loads(log.sig_path.read_text(encoding="utf-8"))["last_seq"]
    assert signed_seq == 3

    # Append a fourth, validly chained entry *without* re-signing the receipt:
    # exactly what a crash between the write and the receipt rewrite looks like.
    extra = {
        "seq": 4,
        "ts": "2026-11-21T00:00:00.000Z",
        "caller": "coding-agent",
        "tool": "fs.read_text_file",
        "args_digest": "sha256:" + "0" * 64,
        "decision": "ALLOW",
        "policy": "baseline",
        "reason": "added out of band",
        "prev_hash": entries[-1]["hash"],
    }
    extra["hash"] = _hash(extra)
    with log.path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(extra) + "\n")

    assert verify(log.path) == (False, "1 unsigned entries after seq 3")
    # ... and the log is not silently accepted as covering 4 entries.
    assert verify(log.path)[1] != "OK (4 entries, signature valid)"


def test_rechained_entries_still_fail_the_signature(tmp_path: Path) -> None:
    log = _new_log(tmp_path)
    _fill(log, 4)
    log.close()

    tampered = _copy_log(log.path, tmp_path / "copy")
    lines = [json.loads(line) for line in _lines(tampered)]
    lines[1]["decision"] = "ALLOW"
    prev = lines[0]["hash"]
    for entry in lines[1:]:  # re-chain everything after the edit
        entry["prev_hash"] = prev
        entry["hash"] = _hash(entry)
        prev = entry["hash"]
    _write_lines(tampered, [json.dumps(entry) for entry in lines])

    # The chain now verifies internally, but its head is not the signed head.
    assert verify(tampered) == (False, "signature invalid")


def test_public_key_path_is_preferred_over_the_receipt(tmp_path: Path) -> None:
    log = _new_log(tmp_path)
    _fill(log, 2)
    log.close()

    trusted = tmp_path / "keys" / "verify.key"
    assert verify(log.path, trusted)[0]

    # A log signed by a different key is rejected even though its own receipt
    # signature checks out: the receipt key alone proves integrity, not origin.
    other = _new_log(tmp_path, "audit2", keys="keys2")
    _fill(other, 1)
    other.close()
    assert verify(other.path)[0]
    assert verify(other.path, trusted) == (False, "signature invalid")


# -- keys and concurrency ---------------------------------------------------


def test_keys_are_reused_across_instances(tmp_path: Path) -> None:
    first = _new_log(tmp_path, "one")
    _fill(first, 2)
    first.close()
    second = _new_log(tmp_path, "two")
    _fill(second, 1)
    second.close()

    key_file = tmp_path / "keys" / "verify.key"
    assert len(key_file.read_bytes()) == 32
    assert (tmp_path / "keys" / "signing.key").stat().st_size == 32
    assert {
        json.loads(first.sig_path.read_text(encoding="utf-8"))["public_key"],
        json.loads(second.sig_path.read_text(encoding="utf-8"))["public_key"],
    } == {key_file.read_bytes().hex()}
    assert verify(first.path)[0] and verify(second.path)[0]
    # Both receipts were signed by the same key: verifying one with the other's
    # public key still succeeds.
    assert verify(first.path, key_file)[0]


def test_concurrent_appends_produce_a_valid_chain(tmp_path: Path) -> None:
    log = _new_log(tmp_path)
    per_thread = 5
    errors: list[BaseException] = []

    def worker(index: int) -> None:
        try:
            for n in range(per_thread):
                log.append(
                    _request(tool=f"shell.run{index}-{n}"),
                    _decision(Verdict.ALLOW if n % 2 else Verdict.DENY),
                )
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    log.close()

    assert not errors
    total = 8 * per_thread
    entries = [json.loads(line) for line in _lines(log.path)]
    assert sorted(entry["seq"] for entry in entries) == list(range(1, total + 1))
    assert verify(log.path) == (True, f"OK ({total} entries, signature valid)")


# -- latest_log + CLI -------------------------------------------------------


def test_latest_log_picks_the_newest_session(tmp_path: Path) -> None:
    assert latest_log(tmp_path) is None
    assert latest_log(tmp_path / "missing") is None

    old = _new_log(tmp_path, "audit")
    _fill(old, 1)
    old.close()
    time.sleep(0.05)
    newer = _new_log(tmp_path, "audit")
    _fill(newer, 2)
    newer.close()

    assert latest_log(tmp_path / "audit") == newer.path


def test_cli_verify_exits_zero_on_a_good_log(tmp_path: Path, monkeypatch) -> None:
    log = _new_log(tmp_path)
    _fill(log, 3)
    log.close()
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(cli.app, ["verify", str(log.path)])
    assert result.exit_code == 0, _output(result)
    assert "OK (3 entries, signature valid)" in _output(result)


def test_cli_verify_defaults_to_the_latest_log(tmp_path: Path, monkeypatch) -> None:
    log = AuditLog(directory=tmp_path / ".admit" / "audit", keys_dir=tmp_path / ".admit" / "keys")
    _fill(log, 2)
    log.close()
    monkeypatch.chdir(tmp_path)  # the default log dir is relative to the cwd

    result = CliRunner().invoke(cli.app, ["verify"])
    assert result.exit_code == 0, _output(result)
    assert "2 entries" in _output(result)


def test_cli_verify_exits_one_on_a_tampered_log(tmp_path: Path, monkeypatch) -> None:
    log = _new_log(tmp_path)
    _fill(log, 3)
    log.close()
    tampered = _copy_log(log.path, tmp_path / "copy")
    lines = _lines(tampered)
    entry = json.loads(lines[1])
    entry["decision"] = "ALLOW"
    lines[1] = json.dumps(entry)
    _write_lines(tampered, lines)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(cli.app, ["verify", str(tampered)])
    assert result.exit_code == 1
    assert "chain broken at entry 2" in _output(result)


def test_cli_verify_reports_a_missing_log(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli.app, ["verify"])
    assert result.exit_code == 1
    assert "no audit log" in _output(result)


def test_cli_verify_rejects_a_missing_explicit_path(tmp_path: Path) -> None:
    result = CliRunner().invoke(cli.app, ["verify", str(tmp_path / "nope.jsonl")])
    assert result.exit_code == 1


def test_verify_of_a_bare_file_without_receipt(tmp_path: Path) -> None:
    path = tmp_path / "session.jsonl"
    path.write_text("", encoding="utf-8")
    assert verify(path) == (False, "no signed receipt")
