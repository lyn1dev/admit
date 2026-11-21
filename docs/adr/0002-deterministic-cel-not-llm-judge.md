# 0002 — Deterministic CEL policies, not an LLM judge

**Status:** Accepted

## Context

Tool-call admission can be decided by a model ("is this call safe?") or by
rules. A model judge is easy to write and tempting to demo, but it is
non-deterministic, prompt-injectable (the attack surface it is meant to police
is its own input), slow, and unauditable: the same call can pass twice and fail
once with no way to explain either outcome. Policy also has to be reviewable by
a human in a pull request.

## Decision

Policies are YAML documents in our own `agentpolicy.dev/v1alpha1` format,
modelled on Kyverno's `ValidatingPolicy`. Each policy matches on
`request.caller` and `request.tool`, then evaluates CEL expressions over
`request.args`. Evaluation is short-circuit-free: every validation runs, and
each failing validation applies its `validationActions` (`Deny`, `Warn`,
`Audit`). Unmatched calls are denied by default; evaluation errors are denied.

## Consequences

- Decisions are reproducible and explainable: the denial names the policy, the
  failing message, and the arguments digest.
- Policy is code-reviewable and testable; the Gherkin suite runs the same
  evaluation path in-process.
- **CEL cannot express everything.** No filesystem resolution, no symlink or
  junction checks, no history, no rate limits. `fs-read-confined` can only
  reject `..` and absolute paths; the optional `confinePath` mutation does the
  real resolution once enabled.
- Authors must be careful with regexes; a weak expression is a weak policy.
  `policies/naive.yaml` exists to show how little a blocklist buys.
- Policy authors need CEL fluency, which is a real onboarding cost.
- Expression errors deny, so a typo takes a tool away rather than opening it.
