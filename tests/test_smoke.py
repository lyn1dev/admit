"""Smoke test: the package imports and exposes a version."""

import admit


def test_version_is_set() -> None:
    assert admit.__version__
