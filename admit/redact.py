"""Secret-pattern redaction for tool outputs: redact(text) -> (text, count).

Applied to every tool result before it reaches the agent. The redacted count
is returned with the text so the result can say how much was removed
(``"redacted": 2``). Pure: no MCP, no network.
"""

from __future__ import annotations

import re

# (name, compiled regex) pairs. Patterns match the common secret shapes, not
# any particular provider: sk_/sk- keys, ghp_/gho_ tokens, AWS AKIA keys,
# Google AIza keys, PEM private keys and KEY=value env lines.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "openai-style key",
        re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    ),
    (
        "sk_ key",
        re.compile(r"\bsk_[A-Za-z0-9]{16,}\b"),
    ),
    (
        "github token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
    ),
    (
        "aws access key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "google api key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35,}\b"),
    ),
    (
        "pem private key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
        ),
    ),
    (
        "env line",
        re.compile(r"(?m)^[A-Za-z_][A-Za-z0-9_]*=.*$"),
    ),
]


def redact(text: str) -> tuple[str, int]:
    """Return ``(redacted_text, count)`` with every secret pattern masked.

    Stub: the real implementation substitutes ``[REDACTED]`` per match and
    returns the total number of replacements.
    """
    raise NotImplementedError
