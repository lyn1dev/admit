"""Files shipped inside the wheel: default policies and the ``admit.yaml`` template.

``policies/*.yaml`` in the repo root is the source of truth; ``tests/test_packaging.py``
fails if these copies drift. Resync with::

    cp policies/baseline.yaml policies/naive.yaml admit/data/policies/
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

_DATA = files("admit.data")


def packaged_policy(name: str) -> Path:
    """Path of a bundled policy file, e.g. ``packaged_policy("baseline.yaml")``."""
    return Path(str(_DATA / "policies" / name))


def config_template() -> str:
    """Text of ``admit.yaml.template`` (``string.Template`` placeholders)."""
    return (_DATA / "admit.yaml.template").read_text(encoding="utf-8")


def resolve_policies(paths: list[Path]) -> list[Path]:
    """Fall back to the bundled copy for a ``policies/<name>.yaml`` missing from disk.

    Lets ``admit serve`` run in any folder: the project's own ``policies/`` wins
    when present, otherwise the policy shipped with Admit is used.
    """
    resolved: list[Path] = []
    for path in paths:
        path = Path(path)
        if not path.exists() and path.parent.name == "policies":
            bundled = packaged_policy(path.name)
            if bundled.is_file():
                resolved.append(bundled)
                continue
        resolved.append(path)
    return resolved
