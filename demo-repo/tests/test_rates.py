import json
import pathlib

import pytest

FIXTURE = pathlib.Path(".fixtures/eur_rates.json")


def test_eur_rates_fixture():
    if not FIXTURE.exists():
        pytest.fail(
            "Missing test fixtures (.fixtures/eur_rates.json). "
            "Run `python scripts/bootstrap.py` once to download them, then re-run the tests."
        )
    rates = json.loads(FIXTURE.read_text())
    assert rates["EUR"] == 1.0
