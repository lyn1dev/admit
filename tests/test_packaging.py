"""Bundled data: policies identical to the repo's policies/, template renders, serve fallback.

If a policy test fails, resync with:
    cp policies/baseline.yaml policies/naive.yaml admit/data/policies/
"""

from __future__ import annotations

from pathlib import Path

import pytest

from admit.config import load_config
from admit.data import config_template, packaged_policy, resolve_policies
from admit.policy import load_policies

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("name", ["baseline.yaml", "naive.yaml"])
def test_packaged_policy_matches_repo_copy(name: str) -> None:
    assert packaged_policy(name).read_bytes() == (REPO_ROOT / "policies" / name).read_bytes(), (
        f"admit/data/policies/{name} drifted: cp policies/{name} admit/data/policies/"
    )


def test_every_repo_policy_is_packaged() -> None:
    for path in (REPO_ROOT / "policies").glob("*.yaml"):
        assert packaged_policy(path.name).is_file(), path.name


def test_packaged_baseline_loads() -> None:
    assert load_policies([packaged_policy("baseline.yaml")])


def test_template_has_placeholders() -> None:
    text = config_template()
    for name in ("$mode", "$token", "$python", "$project", "$fs_block"):
        assert name in text


def test_resolve_policies_falls_back_to_bundled(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    [resolved] = resolve_policies([Path("policies/baseline.yaml")])
    assert resolved == packaged_policy("baseline.yaml")
    local = tmp_path / "policies" / "baseline.yaml"
    local.parent.mkdir()
    local.write_text("# local", encoding="utf-8")
    assert resolve_policies([Path("policies/baseline.yaml")]) == [Path("policies/baseline.yaml")]
    # Non-policies paths are left alone (load_policies reports them).
    assert resolve_policies([Path("other/x.yaml")]) == [Path("other/x.yaml")]


def test_repo_config_still_loads() -> None:
    config = load_config(REPO_ROOT / "admit.yaml")
    assert config.upstreams["shell"].command == "uv"
