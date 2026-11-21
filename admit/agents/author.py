"""Policy Author agent, ADK: audit-log facts -> policy YAML + Gherkin -> diff.

Reads the audit-mode log, compresses paths and commands with the prefix trie
(``admit.trie``), asks the LLM for policy YAML plus one Gherkin scenario,
validates the result (parse YAML, compile CEL, run the scenario), and emits a
unified diff for human approval. ``admit learn --approve`` applies it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class PolicyDraft:
    """Author output: proposed policy, one Gherkin scenario, unified diff."""

    yaml: str  # proposed AgentValidatingPolicy YAML
    gherkin: str  # one scenario exercising the new rules
    diff: str  # unified diff against the current policy file


def propose_policy(audit_log: Path, policies_dir: Path = Path("policies")) -> PolicyDraft:
    """Propose least-privilege policy YAML + Gherkin from audit-mode observations."""
    raise NotImplementedError
