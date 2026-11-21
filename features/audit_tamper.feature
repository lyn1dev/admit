Feature: Tamper-evident audit log
  Each audit entry carries a hash over the previous entry's hash, and the log
  is signed with a local key. Verification reports the first broken link.

  Scenario: An untouched log verifies
    Given an audit log with 4 entries written by the demo session
    When the operator runs "admit audit verify --log audit.jsonl"
    Then verification succeeds
    And the reported entry count is 4

  Scenario: Editing entry 3 breaks the chain at entry 3
    Given an audit log with 4 entries written by the demo session
    When entry 3 is edited so its decision changes from "DENY" to "ALLOW"
    And the operator runs "admit audit verify --log audit.jsonl"
    Then verification fails
    And the error is "chain broken at entry 3"

  Scenario: A re-signed entry is still detected by signature check
    Given an audit log with 4 entries written by the demo session
    When entry 2 is edited and its hash recomputed
    And the operator runs "admit audit verify --log audit.jsonl"
    Then verification fails
    And the error is "signature mismatch"

  Scenario: Arguments are stored as digests, not plaintext
    Given the caller "coding-agent" invokes "shell.run" with args {"command": "pytest -q"}
    When the operator inspects the audit entry for that call
    Then the entry contains no plaintext command
    And the entry contains an "args_digest" starting with "sha256:"
