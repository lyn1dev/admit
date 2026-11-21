"""Redaction: every secret shape is masked, env keys are kept, PATH survives."""

from __future__ import annotations

import pytest

from admit.redact import PATTERNS, PLACEHOLDER, redact

# (pattern name, sample secret text)
SAMPLES = [
    ("sk- key", "export OPENAI=sk-abcdefghij1234567890XYZ done"),
    ("sk_ key", "key sk_test_FAKE_DO_NOT_USE_0000000000 here"),
    ("github token", "token ghp_" + "A" * 36 + " end"),
    ("aws access key", "id AKIAIOSFODNN7EXAMPLE end"),
    ("google api key", "key AIza" + "b" * 35 + " end"),
    (
        "pem private key",
        "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\ndone",
    ),
]


@pytest.mark.parametrize(("name", "text"), SAMPLES)
def test_each_shape_pattern_is_redacted(name: str, text: str) -> None:
    redacted, count = redact(text)
    assert PLACEHOLDER in redacted
    assert count == 1
    # Only the secret goes: surrounding text stays readable.
    assert redacted.replace(PLACEHOLDER, "") != ""


def test_every_pattern_has_a_sample() -> None:
    assert [name for name, _ in PATTERNS] == [name for name, _ in SAMPLES]


def test_sk_underscore_key_matches_dev_token() -> None:
    redacted, count = redact("echo sk_test_FAKE_DO_NOT_USE_0000000000")
    assert count == 1
    assert redacted == "echo [REDACTED]"


def test_env_line_keeps_the_key() -> None:
    redacted, count = redact("API_KEY=s3cr3t-value\n")
    assert count == 1
    assert redacted == "API_KEY=[REDACTED]\n"


@pytest.mark.parametrize(
    "key",
    [
        "OPENAI_API_KEY",
        "GITHUB_SECRET",
        "access_token",
        "DB_PASSWORD",
        "MYSQL_PASSWD",
        "AWS_CREDENTIAL",
        "AUTH_HEADER",
        "SENTRY_DSN",
        "DATABASE_URL",
        "myKey",
    ],
)
def test_secret_looking_keys_are_redacted(key: str) -> None:
    redacted, count = redact(f"{key}=value-with-no-known-shape")
    assert count == 1
    assert redacted == f"{key}={PLACEHOLDER}"


@pytest.mark.parametrize(
    "line",
    ["PATH=/usr/bin:/bin", "HOME=/home/dev", "TERM=xterm-256color", "LANG=en_GB.UTF-8"],
)
def test_ordinary_env_lines_are_untouched(line: str) -> None:
    redacted, count = redact(line)
    assert count == 0
    assert redacted == line


def test_no_double_counting_when_patterns_overlap() -> None:
    # Matches the env-line rule *and* the AWS key shape: counted once.
    redacted, count = redact("AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n")
    assert count == 1
    assert redacted == "AWS_SECRET_ACCESS_KEY=[REDACTED]\n"


def test_counts_every_occurrence() -> None:
    text = "ghp_" + "B" * 36 + " and ghp_" + "C" * 36
    _, count = redact(text)
    assert count == 2


def test_redaction_is_idempotent() -> None:
    once, first = redact("API_KEY=abc\nGITHUB_TOKEN=ghp_" + "D" * 36)
    twice, second = redact(once)
    assert first == 2
    assert second == 0
    assert once == twice


def test_empty_text_is_a_no_op() -> None:
    assert redact("") == ("", 0)


def test_github_token_in_json_is_redacted() -> None:
    from admit.redact import redact

    text, count = redact('"GITHUB_TOKEN": "ghp_FAKE000000000000000000000000000000"')
    assert count == 1 and "ghp_" not in text
