"""Hash-chained, Ed25519-signed audit log. Entry fields: admit.types.AUDIT_FIELDS.

The Policy Author agent reads these JSONL files from .admit/audit/.

Each line carries ``prev_hash`` (the previous entry's ``hash``) and ``hash``, a
SHA-256 over the canonical JSON of the entry without ``hash``. Arguments are
stored only as ``args_digest`` (``sha256:<hex>`` over canonical JSON), so no
secret value or tool output ever lands in the log. After every append the
session receipt (``<session>.sig``) is rewritten atomically with an Ed25519
signature over ``{session, last_seq, last_hash}``, so a crash never leaves an
unsigned tail that silently counts as verified.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from admit.types import AUDIT_FIELDS, Decision, ToolRequest

GENESIS_HASH = "0" * 64
"""``prev_hash`` of the first entry: 64 zeros."""

DEFAULT_AUDIT_DIR = Path(".admit/audit")
DEFAULT_KEYS_DIR = Path(".admit/keys")

_HASHED_FIELDS = tuple(name for name in AUDIT_FIELDS if name != "hash")


# -- canonical serialisation ------------------------------------------------


def _canonical(payload: Any) -> bytes:
    """The one serialisation used for every digest and signature."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _sha256_hex(payload: Any) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def args_digest(args: dict[str, Any] | None) -> str:
    """Digest of the tool arguments. Never returns any part of the values."""
    return "sha256:" + hashlib.sha256(_canonical(args or {})).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _entry_hash(entry: dict[str, Any]) -> str:
    return _sha256_hex({name: entry[name] for name in _HASHED_FIELDS})


# -- keys -------------------------------------------------------------------


def _keypair(keys_dir: Path) -> tuple[SigningKey, VerifyKey]:
    """Load the Ed25519 keypair from ``keys_dir``, generating it on first use.

    ``signing.key`` and ``verify.key`` are raw 32 bytes. Besides the public key
    being distributable on its own, keeping it lets a verifier that is handed
    only a log detect a substituted key in the receipt (see ``verify``).
    """
    keys_dir.mkdir(parents=True, exist_ok=True)
    secret_path = keys_dir / "signing.key"
    public_path = keys_dir / "verify.key"
    if secret_path.exists():
        raw = secret_path.read_bytes()
        if len(raw) != 32:
            raise ValueError(f"{secret_path}: expected 32 raw key bytes, got {len(raw)}")
        signing = SigningKey(raw)
    else:
        signing = SigningKey.generate()
        _write_bytes(secret_path, bytes(signing))
        try:
            os.chmod(secret_path, 0o600)  # best effort: no-op on some filesystems
        except OSError:
            pass
    public = bytes(signing.verify_key)
    if public_path.exists():
        existing = public_path.read_bytes()
        if existing != public:
            raise ValueError(f"{public_path} does not match {secret_path}")
    else:
        _write_bytes(public_path, public)
    return signing, signing.verify_key


def _write_bytes(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _read_public_key(path: Path) -> VerifyKey:
    """Accept a raw 32-byte key file or the hex form used in the receipt."""
    raw = path.read_bytes()
    if len(raw) == 32:
        return VerifyKey(raw)
    return VerifyKey(bytes.fromhex(raw.decode("ascii").strip()))


# -- the log ----------------------------------------------------------------


class AuditLog:
    """One ``admit serve`` session: JSONL entries plus a signed head receipt."""

    def __init__(
        self,
        directory: Path = DEFAULT_AUDIT_DIR,
        keys_dir: Path = DEFAULT_KEYS_DIR,
    ) -> None:
        self.directory = Path(directory)
        self.keys_dir = Path(keys_dir)
        self.directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        self.session = f"{stamp}-{secrets.token_hex(3)}"
        self.path = self.directory / f"{self.session}.jsonl"
        self.sig_path = self.directory / f"{self.session}.sig"
        self._signing, self._verify_key = _keypair(self.keys_dir)
        self._lock = threading.Lock()
        self._seq = 0
        self._last_hash = GENESIS_HASH
        # A resumed session (same directory, same name) continues its chain.
        if self.path.exists():
            self._seq, self._last_hash = _chain_tail(self.path)
        self.path.touch(exist_ok=True)
        with self._lock:
            self._write_receipt()

    # -- public API ---------------------------------------------------------

    def append(self, request: ToolRequest, decision: Decision) -> dict:
        """Append one decision. Returns the entry that was written."""
        with self._lock:
            seq = self._seq + 1
            entry: dict[str, Any] = {
                "seq": seq,
                "ts": _now(),
                "caller": request.caller,
                "tool": request.tool,
                "args_digest": args_digest(request.args),
                "decision": decision.verdict.value,
                "policy": decision.policy,
                "reason": decision.reason,
                "prev_hash": self._last_hash,
            }
            entry["hash"] = _entry_hash(entry)
            line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
            self._seq = seq
            self._last_hash = entry["hash"]
            self._write_receipt()
            return entry

    def close(self) -> None:
        """Write the signed session receipt over the last hash. Idempotent."""
        with self._lock:
            self._write_receipt()

    # -- receipt ------------------------------------------------------------

    def _receipt(self) -> dict[str, Any]:
        body = {"session": self.session, "last_seq": self._seq, "last_hash": self._last_hash}
        signature = self._signing.sign(_canonical(body)).signature
        return {
            "session": self.session,
            "last_seq": self._seq,
            "last_hash": self._last_hash,
            "signature": signature.hex(),
            "public_key": bytes(self._verify_key).hex(),
        }

    def _write_receipt(self) -> None:
        """Atomically replace the receipt so a crash cannot leave a partial one."""
        payload = json.dumps(self._receipt(), sort_keys=True).encode("utf-8")
        _write_bytes(self.sig_path, payload)


def _chain_tail(path: Path) -> tuple[int, str]:
    """(seq, hash) of the last parseable entry, for resuming an existing session."""
    seq, last = 0, GENESIS_HASH
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            seq, last = int(entry["seq"]), str(entry["hash"])
        except (ValueError, KeyError, TypeError):
            break
    return seq, last


def latest_log(directory: Path = DEFAULT_AUDIT_DIR) -> Path | None:
    """Newest ``.jsonl`` session log in ``directory``, or None."""
    directory = Path(directory)
    if not directory.is_dir():
        return None
    candidates = [p for p in directory.glob("*.jsonl") if p.is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: (p.stat().st_mtime_ns, p.name))


# -- verification -----------------------------------------------------------


def verify(log_path: Path, public_key_path: Path | None = None) -> tuple[bool, str]:
    """Return (ok, message), e.g. (False, "chain broken at entry 3").

    ``public_key_path`` (a raw 32-byte key file or its hex) is the key of
    record when given. Without it the key stored in the receipt is used, which
    only proves the log is internally consistent and untouched since the
    receipt was written — not who wrote it, because an attacker able to rewrite
    both the log and the receipt can also substitute a key there.
    """
    log_path = Path(log_path)
    if not log_path.is_file():
        return False, f"no audit log at {log_path}"

    entries: list[dict[str, Any]] = []
    prev_hash = GENESIS_HASH
    lineno = 0
    for lineno, line in enumerate(
        (raw for raw in log_path.read_text(encoding="utf-8").splitlines() if raw.strip()), start=1
    ):
        try:
            entry = json.loads(line)
        except ValueError:
            return False, f"chain broken at entry {lineno}"
        label = entry.get("seq", lineno) if isinstance(entry, dict) else lineno
        if not isinstance(entry, dict) or any(name not in entry for name in _HASHED_FIELDS):
            return False, f"chain broken at entry {label}"
        if entry["seq"] != lineno:
            return False, f"chain broken at entry {label}"
        if entry["prev_hash"] != prev_hash:
            return False, f"chain broken at entry {label}"
        if not isinstance(entry["hash"], str) or entry["hash"] != _entry_hash(entry):
            return False, f"chain broken at entry {label}"
        entries.append(entry)
        prev_hash = entry["hash"]
    count = len(entries)

    receipt = _read_receipt(log_path)
    if receipt is None:
        return False, "no signed receipt"

    try:
        if public_key_path is not None:
            verify_key = _read_public_key(Path(public_key_path))
        else:
            verify_key = VerifyKey(bytes.fromhex(receipt["public_key"]))
        body = {
            "session": receipt["session"],
            "last_seq": receipt["last_seq"],
            "last_hash": receipt["last_hash"],
        }
        verify_key.verify(_canonical(body), bytes.fromhex(receipt["signature"]))
    except (BadSignatureError, ValueError, KeyError, TypeError):
        return False, "signature invalid"

    last_seq = receipt["last_seq"]
    if not isinstance(last_seq, int) or last_seq < 0:
        return False, "signature invalid"
    if last_seq > count:
        return False, f"log truncated: signature covers seq {last_seq}, log has {count} entries"
    if last_seq and entries[last_seq - 1]["hash"] != receipt["last_hash"]:
        return False, "signature invalid"
    if count > last_seq:
        return False, f"{count - last_seq} unsigned entries after seq {last_seq}"
    return True, f"OK ({count} entries, signature valid)"


def _read_receipt(log_path: Path) -> dict[str, Any] | None:
    sig_path = log_path.with_suffix(".sig")
    if not sig_path.is_file():
        return None
    try:
        receipt = json.loads(sig_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(receipt, dict):
        return None
    required = ("session", "last_seq", "last_hash", "signature", "public_key")
    if any(name not in receipt for name in required):
        return None
    return receipt
