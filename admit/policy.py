"""Policy engine: load Kyverno-shaped YAML, compile CEL, decide.

Pure functions, no MCP and no model calls, so everything is unit-testable.
The Red Team agent calls ``evaluate`` directly to test bypass candidates.

Semantics (plan section 5)
--------------------------
* A policy matches when the caller and the tool fnmatch one of its
  ``spec.match.callers`` / ``spec.match.tools`` entries (exact names; ``*`` is a
  glob) and, when ``spec.match.models`` is set, the request model fnmatches one
  of its globs.
* Model trust rule. ``spec.match.models`` globs are matched against
  ``provider/id``. A model of ``""`` (the adapter could not tell) or
  ``antigravity/auto`` (no ``--model`` pinned) cannot prove it is a trusted
  tier, so it is treated as *untrusted*: it matches only a policy that omits
  ``match.models`` entirely, or whose globs are ``*`` or contain ``auto``. Any
  other model must fnmatch a glob.
* No matching policy is default-deny.
* Every validation of every matching policy runs; a ``false`` result applies
  that policy's action with its message. Strictest action wins:
  Deny > Warn > Audit. An expression that raises or returns a non-boolean is
  an evaluation error and always Deny.
* ``Mode.AUDIT`` turns the would-be Deny/Warn into ``WOULD_DENY`` (allowed, but
  logged). Evaluation errors stay ``DENY``: audit mode observes, it does not
  fail open on a broken policy.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

import celpy
import yaml
from celpy import celtypes
from celpy.adapter import json_to_cel

from admit.types import Decision, Mode, ToolRequest, Verdict

API_VERSION = "agentpolicy.dev/v1alpha1"
KIND = "AgentValidatingPolicy"
ACTIONS: tuple[str, ...] = ("Deny", "Warn", "Audit")

#: Models that cannot prove they belong to a trusted tier (see module docstring).
UNTRUSTED_MODELS: frozenset[str] = frozenset({"", "antigravity/auto"})

#: Denial hint for a chained command: the allowlist denies the whole chain, so
#: the agent has to retry the allowed parts one command at a time (plan section 16).
CHAINED_COMMAND_HINT = (
    "Run each allowed command on its own, e.g. python -m pytest. "
    "Continue without blocked steps and tell the user what was blocked."
)

# celpy environments are cheap and reusable; compile every expression once at load.
_ENV = celpy.Environment()

_ACTION_VERDICT: dict[str, Verdict] = {
    "Deny": Verdict.DENY,
    "Warn": Verdict.WARN,
    "Audit": Verdict.WOULD_DENY,
}

_RANK: dict[Verdict, int] = {Verdict.DENY: 3, Verdict.WARN: 2, Verdict.WOULD_DENY: 1}


class Validation(NamedTuple):
    """One compiled CEL validation: its program, the message it denies with, its source."""

    program: Any
    message: str
    source: str


@dataclass(frozen=True)
class Policy:
    """One compiled ``AgentValidatingPolicy``."""

    name: str
    callers: list[str]
    tools: list[str]
    models: list[str] | None  # None = any model
    validations: list[Validation]
    actions: list[str]  # Deny | Warn | Audit (one action per validation result)


# -- loading ----------------------------------------------------------------


def load_policies(paths: list[Path]) -> list[Policy]:
    """Parse and compile every policy document in ``paths``.

    Raises ``ValueError`` for a missing file, malformed YAML, a wrong
    apiVersion/kind, a missing name/match, an unknown action or a CEL
    expression that does not compile, and for two documents with the same name.
    Fail closed at startup: a half-loaded policy set is never returned.
    """
    loaded: list[Policy] = []
    seen: dict[str, Path] = {}
    for path in paths:
        path = Path(path)
        for policy in _load_file(path):
            if policy.name in seen:
                raise ValueError(
                    f"invalid policy {path}#{policy.name}: duplicate policy name "
                    f"(already defined in {seen[policy.name]})"
                )
            seen[policy.name] = path
            loaded.append(policy)
    return loaded


def _load_file(path: Path) -> list[Policy]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"invalid policy {path}: cannot read: {exc}") from exc
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid policy {path}: not valid YAML: {exc}") from exc
    policies: list[Policy] = []
    for index, document in enumerate(documents, start=1):
        if document is None:  # comment-only document
            continue
        policies.append(_parse_document(path, index, document))
    return policies


def _parse_document(path: Path, index: int, document: Any) -> Policy:
    if not isinstance(document, dict):
        raise ValueError(f"invalid policy {path}#{index}: a document must be a mapping")
    metadata = document.get("metadata")
    name = metadata.get("name") if isinstance(metadata, dict) else None
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"invalid policy {path}#{index}: missing metadata.name")
    name = name.strip()

    def fail(message: str) -> ValueError:
        return ValueError(f"invalid policy {path}#{name}: {message}")

    if document.get("apiVersion") != API_VERSION:
        raise fail(f"apiVersion must be {API_VERSION!r}, got {document.get('apiVersion')!r}")
    if document.get("kind") != KIND:
        raise fail(f"kind must be {KIND!r}, got {document.get('kind')!r}")
    spec = document.get("spec")
    if not isinstance(spec, dict):
        raise fail("missing spec block")
    match = spec.get("match")
    if not isinstance(match, dict):
        raise fail("missing spec.match block")
    callers = _names(match.get("callers"), fail, "spec.match.callers")
    tools = _names(match.get("tools"), fail, "spec.match.tools")
    models = match.get("models")
    if models is not None:
        models = _names(models, fail, "spec.match.models")
    actions = _actions(spec.get("validationActions"), fail)
    validations = _validations(spec.get("validations"), fail)
    return Policy(
        name=name,
        callers=callers,
        tools=tools,
        models=models,
        validations=validations,
        actions=actions,
    )


def _names(value: Any, fail: Callable[[str], ValueError], where: str) -> list[str]:
    """A non-empty list of non-empty strings (a bare string counts as a list of one)."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not value:
        raise fail(f"{where} must be a non-empty list of strings")
    names: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise fail(f"{where} must contain non-empty strings")
        names.append(item.strip())
    return names


def _actions(value: Any, fail: Callable[[str], ValueError]) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not value:
        raise fail("validationActions must be a non-empty list")
    actions: list[str] = []
    for item in value:
        if item not in ACTIONS:
            raise fail(f"unknown validationAction {item!r} (expected one of: {', '.join(ACTIONS)})")
        actions.append(item)
    return actions


def _validations(value: Any, fail: Callable[[str], ValueError]) -> list[Validation]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise fail("validations must be a list")
    validations: list[Validation] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise fail(f"validations[{index}] must be a mapping with an 'expression'")
        source = raw.get("expression")
        if not isinstance(source, str) or not source.strip():
            raise fail(f"validations[{index}] is missing a CEL 'expression'")
        try:
            program = _ENV.program(_ENV.compile(source))
        except Exception as exc:  # noqa: BLE001 - any compile failure is fail-closed
            raise fail(
                f"policy evaluation error: validations[{index}] does not compile: {exc}"
            ) from exc
        message = raw.get("message")
        if not isinstance(message, str) or not message.strip():
            message = f"validation failed: {source}"
        validations.append(Validation(program, message, source))
    return validations


# -- evaluation -------------------------------------------------------------


def evaluate(request: ToolRequest, policies: list[Policy], mode: Mode = Mode.ENFORCE) -> Decision:
    """Decide one request. Never raises: anything unexpected is a DENY."""
    try:
        return _evaluate(request, list(policies or ()), mode)
    except Exception as exc:  # noqa: BLE001 - fail closed on anything
        return Decision(Verdict.DENY, None, f"policy evaluation error: {type(exc).__name__}: {exc}")


@dataclass(frozen=True)
class _Failure:
    """One failed validation, with the verdict its policy's action asks for."""

    verdict: Verdict
    policy: str
    reason: str
    fail_closed: bool = False  # evaluation error: audit mode must not soften it


def _evaluate(request: ToolRequest, policies: list[Policy], mode: Mode) -> Decision:
    matching = [policy for policy in policies if _matches(policy, request)]
    if not matching:
        reason = f"no policy grants {request.tool} to {request.caller}"
        verdict = Verdict.WOULD_DENY if mode == Mode.AUDIT else Verdict.DENY
        return Decision(verdict, None, reason)

    failures: list[_Failure] = []
    for policy in matching:
        action = _strictest_action(policy)
        for validation in policy.validations:
            failed, error = _run(validation, request)
            if error is not None:
                failures.append(
                    _Failure(
                        Verdict.DENY,
                        policy.name,
                        f"policy evaluation error in {policy.name}: {error}",
                        fail_closed=True,
                    )
                )
            elif failed:
                failures.append(_Failure(action, policy.name, validation.message))

    if not failures:
        names = ", ".join(policy.name for policy in matching)
        return Decision(Verdict.ALLOW, matching[0].name, f"allowed by {names}")

    chosen = failures[0]
    for candidate in failures[1:]:
        if _RANK[candidate.verdict] > _RANK[chosen.verdict]:
            chosen = candidate
        elif _RANK[candidate.verdict] == _RANK[chosen.verdict] and (
            candidate.fail_closed and not chosen.fail_closed
        ):
            chosen = candidate

    verdict = chosen.verdict
    if mode == Mode.AUDIT and verdict in (Verdict.DENY, Verdict.WARN) and not chosen.fail_closed:
        verdict = Verdict.WOULD_DENY
    return Decision(verdict, chosen.policy, chosen.reason, _hint(request, verdict, chosen.policy))


def _matches(policy: Policy, request: ToolRequest) -> bool:
    if not _any_glob(policy.callers, request.caller):
        return False
    if not _any_glob(policy.tools, request.tool):
        return False
    if policy.models is None:
        return True
    model = (request.model or "").strip()
    if model in UNTRUSTED_MODELS:
        # Unproven trust tier: only an unrestricted or explicitly-auto policy may match.
        return any(_is_untrusted_glob(pattern) for pattern in policy.models)
    return _any_glob(policy.models, model)


def _any_glob(patterns: list[str], value: str) -> bool:
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)


def _is_untrusted_glob(pattern: str) -> bool:
    text = pattern.strip().lower()
    return text == "*" or "auto" in text


def _strictest_action(policy: Policy) -> Verdict:
    return max((_ACTION_VERDICT[action] for action in policy.actions), key=_RANK.__getitem__)


def _run(validation: Validation, request: ToolRequest) -> tuple[bool, str | None]:
    """Evaluate one validation: ``(failed, error)``; exactly one of them is set."""
    try:
        result = validation.program.evaluate({"request": json_to_cel(request.to_cel())})
    except Exception as exc:  # noqa: BLE001 - CEL eval errors are fail-closed
        return False, f"{type(exc).__name__}: {exc}"
    if not isinstance(result, celtypes.BoolType):  # celtypes.BoolType, never a plain bool
        return False, f"expression returned {type(result).__name__}, not a boolean"
    return not bool(result), None


def _hint(request: ToolRequest, verdict: Verdict, policy: str | None) -> str | None:
    if (
        verdict is Verdict.DENY
        and request.tool == "shell.run"
        and policy is not None
        and "shell" in policy.lower()
    ):
        return CHAINED_COMMAND_HINT
    return None


__all__ = [
    "ACTIONS",
    "API_VERSION",
    "CHAINED_COMMAND_HINT",
    "KIND",
    "Policy",
    "UNTRUSTED_MODELS",
    "Validation",
    "evaluate",
    "load_policies",
]
