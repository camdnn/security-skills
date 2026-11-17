# PLAN.md template

`docs/security/PLAN.md` hands `security-scan` the pre-findings and where to look
first. Keep it to **about 100 lines**. Replace each `<...>` placeholder.

A **pre-finding** is a mismatch between the developer's stated intent (an answer
or business rule) and the code, noticed while building context. It is a lead
for the scan, not a finding: do not score it or give it a `SEC-` identifier.

---

```markdown
# Security plan

Commit: <short SHA or "unknown"> · Date: <YYYY-MM-DD>

## Pre-findings

| # | Business rule | Location | Mismatch | Likely check |
| --- | --- | --- | --- | --- |
| P-1 | BR-<n> | `<file>:<start>-<end>` | <what the rule requires and what the code does instead> | <access-control-check / ...> |

## Recommended scan focus

1. <Entry point, module or check to scan first, and why (risk, sensitive data, a pre-finding)>.

## Assumptions

- <Each `assumed` answer that the scan's conclusions depend on, by question ID>.

## Limitations

- <Scope limits, e.g. not a Node.js/TypeScript Express app, paths excluded, low-confidence areas.>
```
