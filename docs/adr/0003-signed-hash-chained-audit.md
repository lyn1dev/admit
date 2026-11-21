# 0003 — Signed, hash-chained audit log

**Status:** Accepted

## Context

A decision that is not recorded cannot be reviewed after an incident. A plain
JSONL log is worse than nothing if an attacker who reaches the host can rewrite
it, because it invites false confidence. We need evidence that an entry was
written by Admit and that no earlier entry was changed or removed.

## Decision

Every decision — allow, deny, warn, audit-only, and pin mismatch — appends one
JSON line. Each entry stores `prev_hash`, a SHA-256 digest over the previous
entry, and `args_digest`, a SHA-256 digest of the canonicalised arguments
instead of the arguments themselves. The latest hash is signed with an Ed25519
key. `admit audit verify` walks the chain and reports the first broken link
(`chain broken at entry 3`) or a signature mismatch.

## Consequences

- Tampering is detectable with no external service: an edit breaks the chain
  from that entry onward, and recomputing the chain breaks the signature.
- **Arguments are stored as digests, so no secrets leak into logs** — but
  incident review also cannot see the command that was blocked. Reproducing a
  denial requires the original request from the agent-side logs.
- An attacker with the signing key can forge a fresh chain. **The key is local
  for the prototype; production must use KMS or an HSM** and should ship the
  chain head to append-only external storage.
- Truncating the newest entries is not detectable by the chain alone; operators
  must compare the last entry hash against a separately recorded head.
- Logs grow without bound until rotation is added.
