"""Secret-pattern redaction for tool outputs: redact(text) -> (text, count).

Applied to every tool result before it reaches the agent. The redacted count
is returned with the text so the result can say how much was removed
(``"redacted": 2``). Pure: no MCP, no network.
"""

from __future__ import annotations

import re

PLACEHOLDER = "[REDACTED]"

# An env line is only a secret when its KEY NAME looks like one. ``PATH=/usr/bin``
# must survive untouched.
ENV_KEY_WORDS: tuple[str, ...] = (
    "DATABASE_URL",
    "CREDENTIAL",
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "AUTH",
    "DSN",
    "KEY",
)

_ENV_KEY_ALT = "|".join(ENV_KEY_WORDS)

# Name/value split so the replacement can keep the key (``API_KEY=[REDACTED]``).
ENV_LINE_KEY = "key"
ENV_LINE_VALUE = "value"

# (name, compiled regex) pairs. Patterns match the common secret shapes, not
# any particular provider: sk-/sk_ keys, ghp_/gho_ tokens, AWS AKIA keys,
# Google AIza keys, PEM private keys and KEY=value env lines.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "sk- key",
        re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{16,}"),
    ),
    (
        # sk_test_FAKE_...: the body itself may contain underscores.
        "sk_ key",
        re.compile(r"(?<![A-Za-z0-9_])sk_[A-Za-z0-9_]{8,}[A-Za-z0-9]"),
    ),
    (
        "github token",
        re.compile(r"(?<![A-Za-z0-9_])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}"),
    ),
    (
        "aws access key",
        re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![0-9A-Z])"),
    ),
    (
        "google api key",
        re.compile(r"(?<![A-Za-z0-9_])AIza[0-9A-Za-z_-]{35,}"),
    ),
    (
        "pem private key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
        ),
    ),
]

# Env lines are handled after the shape patterns (see `redact`): doing it the
# other way round would count the same secret twice.
ENV_LINE = re.compile(
    rf"(?im)^(?P<{ENV_LINE_KEY}>(?=[A-Za-z0-9_]*?(?:{_ENV_KEY_ALT}))[A-Za-z_][A-Za-z0-9_]*)"
    rf"[ \t]*=[ \t]*(?P<{ENV_LINE_VALUE}>[^\r\n]*)$"
)


def _redact_env_lines(text: str) -> tuple[str, int]:
    """Mask the value of secret-looking ``KEY=value`` lines, keeping the key."""
    count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal count
        value = match.group(ENV_LINE_VALUE)
        if not value or value.strip() == PLACEHOLDER:
            return match.group(0)  # already redacted / empty: not a secret
        count += 1
        return f"{match.group(ENV_LINE_KEY)}={PLACEHOLDER}"

    return ENV_LINE.sub(replace, text), count


def redact(text: str) -> tuple[str, int]:
    """Return ``(redacted_text, count)`` with every secret pattern masked.

    Each match becomes ``[REDACTED]``. Env lines are masked first so a secret
    that also matches a shape pattern (``AWS_SECRET_ACCESS_KEY=AKIA...``) is
    counted once, not twice.
    """
    if not text:
        return text, 0
    redacted, count = _redact_env_lines(text)
    for _name, pattern in PATTERNS:
        redacted, hits = pattern.subn(PLACEHOLDER, redacted)
        count += hits
    return redacted, count
