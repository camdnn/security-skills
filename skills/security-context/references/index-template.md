# SECURITY-CONTEXT.md template

`docs/security/SECURITY-CONTEXT.md` is the index `security-scan` loads first.
Keep it to **about 150 lines**; if it does not fit, shorten entries rather than
dropping a section. Replace each `<...>` placeholder; write "Unknown" rather
than guessing. Cite the [question bank](question-bank.md) ID each section draws
on, so a reader can find the answer in `ANSWERS.md`.

Business rules live in this file in v1. Keep any `BR-n` number a canned or
developer answer gives; number the other rules after the highest one, in the
order you record them, and keep a number once given: findings cite it in
`context_ref`. State each rule as intended behaviour, not as what the code does.

The module table's Link column stays `—` until module files exist.

Never write secret values here: give only the location and kind of secret.

---

```markdown
# Security context

Commit: <short SHA or "unknown"> · Date: <YYYY-MM-DD> · Interview: <interactive | unattended> · Confidence: <high | medium | low>

## Purpose

<One or two sentences. (PURPOSE)>

Scope: <paths in scope>; excluded: <paths excluded>. (SCOPE)

## Roles

| Role | Description |
| --- | --- |
| <role> | <what it is for> |

## Permission matrix

| Action | <role> | <role> |
| --- | --- | --- |
| <action on a resource> | <allowed / own only / denied> | <...> |

## Business rules

- **BR-1**: <intended behaviour>. Source: <question ID>, <answered / derived / assumed>. Code: `<file>:<line>`.

## Sensitive data

| Data | Where | Sensitivity |
| --- | --- | --- |
| <data> | <model, field or file> | <high / medium / low> |

## Trust boundaries

- <Untrusted input or external service, and where the code receives it>. (TRUST-BOUNDARIES)

## Authentication

<Mechanism and how it is applied; public routes.> (AUTHENTICATION)

## Global controls

| Control | Status | Where |
| --- | --- | --- |
| <CORS / CSRF / rate limiting / headers / validation / error handling / logging> | <present / absent / partial> | `<file>:<line>` |

## Modules

| Module | Path | Risk | Owner | Link | Last verified commit |
| --- | --- | --- | --- | --- | --- |
| <name> | `<path>/` | <high / medium / low> | <owner or "unknown"> | — | <short SHA> |
```
