Feature: Default deny and fail closed
  A tool call is allowed only if at least one policy matches the caller and
  tool. Anything unmatched, or anything Admit cannot evaluate, is denied.

  Scenario: An unknown tool is denied because nothing grants it
    Given the caller "coding-agent" holds a token for the admit proxy
    And the proxy runs with policies from "policies/baseline.yaml" in enforce mode
    When the caller invokes "fs.write_file" with args {"path": "notes.txt", "content": "hi"}
    Then the decision is "DENY"
    And the policy is null
    And the reason is "no policy grants fs.write_file to coding-agent"

  Scenario: A caller with no matching policies is denied
    Given the caller "ci-bot" holds a token for the admit proxy
    And the proxy runs with policies from "policies/baseline.yaml" in enforce mode
    When the caller invokes "shell.run" with args {"command": "git status"}
    Then the decision is "DENY"
    And the reason is "no policy grants shell.run to ci-bot"

  Scenario: An unparseable CEL expression fails closed
    Given a policy file whose shell-allowlist expression is "request.args.command.matches(^pytest$"
    And the proxy runs with policies from that file in enforce mode
    When the caller "coding-agent" invokes "shell.run" with args {"command": "pytest"}
    Then the decision is "DENY"
    And the reason mentions "policy evaluation error"
    And no call is forwarded to any upstream server

  Scenario: A malformed policy document fails closed
    Given a policy file missing the "match" block
    And the proxy runs with policies from that file in enforce mode
    When the caller "coding-agent" invokes "shell.run" with args {"command": "git status"}
    Then the decision is "DENY"
    And the reason mentions "invalid policy"
