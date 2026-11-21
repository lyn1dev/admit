"""BDD steps for ``features/default_deny.feature`` and ``features/audit_mode.feature``.

The scenarios run in-process against ``admit.policy.evaluate``: there is no
proxy and no upstream here, so two step-level conventions keep the Gherkin
honest about that.

* "the decision is ALLOW" reports what the *caller* observes. A ``WOULD_DENY``
  verdict (audit action or audit mode) is forwarded by the proxy (plan
  section 4), so it counts as ALLOW; "the audit entry records ..." asserts the
  engine verdict itself.
* A policy file that fails to load means ``admit serve`` refuses to start, so
  the call is never evaluated. The steps then report the fail-closed DENY a
  running proxy would hand back (invalid file, or a CEL compile error at load).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from pytest_bdd import given, parsers, scenarios, then, when

from admit.policy import API_VERSION, KIND, evaluate, load_policies
from admit.types import Decision, Mode, ToolRequest, Verdict

REPO = Path(__file__).resolve().parents[1]

scenarios("default_deny.feature")
scenarios("audit_mode.feature")


@pytest.fixture
def ctx() -> dict[str, Any]:
    return {
        "caller": "coding-agent",
        "policy_file": None,
        "mode": Mode.ENFORCE,
        "policies": [],
        "load_error": None,
        "decision": None,
        "forwarded": [],
    }


# -- helpers ----------------------------------------------------------------


def _mode(text: str) -> Mode:
    return Mode(text.strip().lower())


def _path(text: str) -> Path:
    candidate = Path(text)
    return candidate if candidate.is_absolute() else REPO / candidate


def _document(
    *,
    name: str,
    callers: tuple[str, ...] = ("coding-agent",),
    tools: tuple[str, ...] = ("shell.run",),
    validations: list[dict[str, Any]] | None = None,
    actions: tuple[str, ...] = ("Deny",),
) -> dict[str, Any]:
    if validations is None:
        validations = [{"expression": 'request.args.command == "pytest"', "message": "only pytest"}]
    return {
        "apiVersion": API_VERSION,
        "kind": KIND,
        "metadata": {"name": name},
        "spec": {
            "match": {"callers": list(callers), "tools": list(tools)},
            "validations": validations,
            "validationActions": list(actions),
        },
    }


def _write(tmp_path: Path, document: dict[str, Any]) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _observed(decision: Decision) -> str:
    """What the caller sees: WOULD_DENY is forwarded, every other verdict stands."""
    if decision.verdict is Verdict.WOULD_DENY:
        return Verdict.ALLOW.value
    return decision.verdict.value


def _load(ctx: dict[str, Any]) -> None:
    if ctx["policies"] or ctx["load_error"] is not None:
        return
    assert ctx["policy_file"] is not None, "no policy file was set up"
    try:
        ctx["policies"] = load_policies([ctx["policy_file"]])
    except ValueError as exc:  # fail closed: admit serve would refuse to start
        ctx["policies"] = []
        ctx["load_error"] = exc


# -- given ------------------------------------------------------------------


@given(parsers.parse('the caller "{caller}" holds a token for the admit proxy'))
def caller_holds_a_token(ctx: dict[str, Any], caller: str) -> None:
    ctx["caller"] = caller


@given(parsers.parse('the proxy runs with policies from "{path}" in {mode} mode'))
def proxy_with_policy_file(ctx: dict[str, Any], path: str, mode: str) -> None:
    ctx["policy_file"] = _path(path)
    ctx["mode"] = _mode(mode)


@given(parsers.parse("the proxy runs with policies from that file in {mode} mode"))
def proxy_with_that_policy_file(ctx: dict[str, Any], mode: str) -> None:
    ctx["mode"] = _mode(mode)


@given(parsers.parse('a policy file whose shell-allowlist expression is "{expression}"'))
def policy_with_expression(ctx: dict[str, Any], tmp_path: Path, expression: str) -> None:
    document = _document(
        name="shell-allowlist",
        validations=[
            {"expression": expression, "message": "Command is not on the shell allowlist"}
        ],
    )
    ctx["policy_file"] = _write(tmp_path, document)


@given('a policy file missing the "match" block')
def policy_missing_match(ctx: dict[str, Any], tmp_path: Path) -> None:
    document = _document(name="shell-allowlist")
    del document["spec"]["match"]
    ctx["policy_file"] = _write(tmp_path, document)


@given(
    parsers.parse(
        'a policy granting "{tool}" to "{caller}" with validations that require '
        '"{command}" and validationActions [{action}]'
    )
)
def policy_granting(
    ctx: dict[str, Any], tmp_path: Path, tool: str, caller: str, command: str, action: str
) -> None:
    document = _document(
        name="audit-only-grant",
        callers=(caller,),
        tools=(tool,),
        validations=[
            {"expression": f'request.args.command == "{command}"', "message": f"only {command}"}
        ],
        actions=(action,),
    )
    ctx["policy_file"] = _write(tmp_path, document)


# -- when -------------------------------------------------------------------


@when(parsers.parse('the caller "{caller}" invokes "{tool}" with args {args}'))
def named_caller_invokes(ctx: dict[str, Any], caller: str, tool: str, args: str) -> None:
    _invoke(ctx, caller, tool, args)


@when(parsers.parse('the caller invokes "{tool}" with args {args}'))
def caller_invokes(ctx: dict[str, Any], tool: str, args: str) -> None:
    _invoke(ctx, ctx["caller"], tool, args)


def _invoke(ctx: dict[str, Any], caller: str, tool: str, args: str) -> None:
    ctx["caller"] = caller
    request = ToolRequest(caller, tool, json.loads(args.strip()))
    _load(ctx)
    if ctx["load_error"] is not None:
        # The proxy would not start; the call is denied and never forwarded.
        ctx["decision"] = Decision(Verdict.DENY, None, str(ctx["load_error"]))
        return
    decision = evaluate(request, ctx["policies"], ctx["mode"])
    ctx["decision"] = decision
    if decision.allowed:
        ctx["forwarded"].append(tool)


# -- then -------------------------------------------------------------------


@then(parsers.parse('the decision is "{verdict}"'))
def decision_is(ctx: dict[str, Any], verdict: str) -> None:
    assert _observed(ctx["decision"]) == verdict.upper()


@then("the policy is null")
def policy_is_null(ctx: dict[str, Any]) -> None:
    assert ctx["decision"].policy is None


@then(parsers.parse('the policy is "{policy}"'))
def policy_is(ctx: dict[str, Any], policy: str) -> None:
    assert ctx["decision"].policy == policy


@then(parsers.parse('the reason is "{reason}"'))
def reason_is(ctx: dict[str, Any], reason: str) -> None:
    assert ctx["decision"].reason == reason


@then(parsers.parse('the reason mentions "{text}"'))
def reason_mentions(ctx: dict[str, Any], text: str) -> None:
    assert text in ctx["decision"].reason


@then("no call is forwarded to any upstream server")
def no_call_forwarded(ctx: dict[str, Any]) -> None:
    assert ctx["forwarded"] == []


@then("the call is forwarded to the shell server")
def forwarded_to_shell_server(ctx: dict[str, Any]) -> None:
    assert "shell.run" in ctx["forwarded"]


@then(parsers.parse('the audit entry records "{verdict}" for policy "{policy}"'))
def audit_entry_for_policy(ctx: dict[str, Any], verdict: str, policy: str) -> None:
    assert ctx["decision"].verdict.value == verdict
    assert ctx["decision"].policy == policy


@then(parsers.parse('the audit entry records "{verdict}" for that policy'))
def audit_entry_for_that_policy(ctx: dict[str, Any], verdict: str) -> None:
    assert ctx["decision"].verdict.value == verdict
    assert ctx["decision"].policy is not None
