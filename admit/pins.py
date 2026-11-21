"""Tool pinning: SHA-256 of name + description + input schema in .admit/pins.json.

Records every upstream tool on first serve (or ``admit serve --pin``) and
compares later runs against it: a changed tool is hidden from ``tools/list``,
its calls are DENY and a ``PIN_MISMATCH`` entry is logged (rug-pull and
tool-poisoning protection).
"""

from __future__ import annotations

from pathlib import Path


def tool_digest(name: str, description: str, input_schema: dict) -> str:
    """SHA-256 over ``name + description + canonical JSON(input_schema)``."""
    raise NotImplementedError


def load_pins(path: Path) -> dict:
    """Load ``.admit/pins.json`` (empty dict when missing)."""
    raise NotImplementedError


def save_pins(path: Path, pins: dict) -> None:
    """Persist pins, creating ``.admit/`` as needed."""
    raise NotImplementedError


def compare(current: dict, pinned: dict) -> set[str]:
    """Return tool names whose current digest differs from the pinned one."""
    raise NotImplementedError
