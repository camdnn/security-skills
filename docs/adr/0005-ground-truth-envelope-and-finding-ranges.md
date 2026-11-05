# Ground truth uses an explicit envelope and findings always use ranges

Every `expected.json` is an object with a required `truth` array and an optional `must_not_find` array; truth entries have no category and a must-not-find rule is exactly `{file, cwe_family}`. Findings must always provide a non-null `end_line`, repeating `line` for a single-line finding. These explicit shapes make ground truth unambiguous for the matcher and reject incomplete agent output before it can affect a score.

## Consequences

Both schemas reject undeclared fields. Finding identifiers, CWE IDs, OWASP IDs, and skill names use their declared formats, so malformed metadata becomes a failed trial instead of silently entering reports. The matcher may defensively treat a missing range end as a single line for unchecked in-memory inputs, but schema-valid `findings.json` never omits or nulls `end_line`.
