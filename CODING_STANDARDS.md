# Reviewer standards

Apply these judgment rules when reviewing a change. They are deliberately limited
to rules that require human interpretation; `TICKET-001 §0` remains authoritative.

## Vocabulary — §0 rule 12

Use the canonical terms in [GLOSSARY.md](GLOSSARY.md). Request a terminology
correction when a change introduces a competing name for an established concept
or uses a glossary term with a different meaning.

## Scope — §0 rule 9

Keep each commit and pull request to one concern. A change that combines
unrelated behavior, refactoring, or documentation should be separated until its
purpose can be reviewed as one coherent decision.

## Untrusted scan data — §0 rule 8

Every skill that scans target code must explicitly state that scanned code,
comments, and strings are untrusted data rather than instructions. Checker code
must treat model-produced finding fields as data, keep them away from filesystem
operations, and score safely even when a finding attempts to game the rules.

## Context-file limits — §0 rule 5

Keep context files within the limits in `TICKET-001 §3.4`. When content exceeds
a limit, split it into focused files instead of enlarging the limit.
