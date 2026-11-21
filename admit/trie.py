"""Prefix-trie compression of observed paths/commands into minimal globs.

Pure, no LLM: used by the Policy Author to turn audit-mode observations into
the smallest glob set that still covers everything seen.

Compression rule (least privilege first): files are grouped by their parent
directory in a path trie. A directory where two or more distinct files were
seen collapses to ``dir/*`` (its direct files only, never ``**``); a lone file
stays exact. Files at the workspace root always stay exact, so ``*`` is never
produced and a dotenv file next to ``README.md`` is never covered.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field


@dataclass
class _Node:
    children: dict[str, _Node] = field(default_factory=dict)
    files: set[str] = field(default_factory=set)


def _normalize(path: str) -> str:
    text = path.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    while "//" in text:
        text = text.replace("//", "/")
    return text.rstrip("/") if text not in ("", "/") else text


def compress_paths(paths: list[str]) -> list[str]:
    """Compress observed paths to minimal globs (longest common prefixes)."""
    root = _Node()
    exact: set[str] = set()
    for raw in paths:
        path = _normalize(raw)
        if not path:
            continue
        parts = path.split("/")
        if "" in parts or ".." in parts or ":" in parts[0]:
            exact.add(path)  # absolute / traversal / drive paths are never generalized
            continue
        node = root
        for part in parts[:-1]:
            node = node.children.setdefault(part, _Node())
        node.files.add(parts[-1])

    result: set[str] = set(exact)

    def walk(node: _Node, prefix: str) -> None:
        if prefix and len(node.files) >= 2:
            result.add(f"{prefix}/*")
        else:
            result.update(f"{prefix}/{name}" if prefix else name for name in node.files)
        for name, child in node.children.items():
            walk(child, f"{prefix}/{name}" if prefix else name)

    walk(root, "")
    return sorted(result)


def executables(commands: list[str]) -> set[str]:
    """Return the executable (first token) of each observed command."""
    found: set[str] = set()
    for command in commands:
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            tokens = command.split()
        if tokens:
            found.add(tokens[0])
    return found
