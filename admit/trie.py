"""Prefix-trie compression of observed paths/commands into minimal globs.

Pure, no LLM: used by the Policy Author to turn audit-mode observations into
the smallest glob set that still covers everything seen.
"""

from __future__ import annotations


def compress_paths(paths: list[str]) -> list[str]:
    """Compress observed paths to minimal globs (longest common prefixes)."""
    raise NotImplementedError


def executables(commands: list[str]) -> set[str]:
    """Return the executable (first token) of each observed command."""
    raise NotImplementedError
