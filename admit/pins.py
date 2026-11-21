"""Tool pinning: SHA-256 of name + description + input schema in .admit/pins.json.

Records every upstream tool on first serve (or ``admit serve --pin``) and
compares later runs against it: a changed tool is hidden from ``tools/list``,
its calls are DENY and a ``PIN_MISMATCH`` entry is logged (rug-pull and
tool-poisoning protection). Pure file I/O, no MCP.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def tool_digest(name: str, description: str, input_schema: dict) -> str:
    """SHA-256 over ``name + description + canonical JSON(input_schema)``."""
    canonical = json.dumps(
        input_schema or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    digest = hashlib.sha256()
    digest.update((name or "").encode("utf-8"))
    digest.update((description or "").encode("utf-8"))
    digest.update(canonical.encode("utf-8"))
    return digest.hexdigest()


def load_pins(path: Path) -> dict:
    """Load ``.admit/pins.json`` (empty dict when missing)."""
    path = Path(path)
    if not path.is_file():
        return {}
    raw: Any = json.loads(path.read_text(encoding="utf-8") or "{}")
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: pins file must contain a JSON object")
    return {str(name): str(digest) for name, digest in raw.items()}


def save_pins(path: Path, pins: dict) -> None:
    """Persist pins, creating ``.admit/`` as needed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(dict(sorted(pins.items())), indent=2) + "\n", encoding="utf-8"
    )


def compare(current: dict, pinned: dict) -> set[str]:
    """Return tool names whose current digest differs from the pinned one."""
    return {
        name
        for name, digest in current.items()
        if name in pinned and pinned[name] != digest
    }
