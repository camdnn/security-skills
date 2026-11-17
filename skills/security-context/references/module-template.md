# Module file template

`docs/security/modules/<module>.md` describes one module for `security-scan`.
Keep it to **about 200 lines**; split the module if it does not fit. The front
matter is read by [stale_modules.py](../../security-scan/scripts/stale_modules.py):
`covers` lists the module's paths or globs relative to the target root, and
`commit` is the commit the file was last verified against (`unknown` outside
Git, which always counts as stale).

Cite business rules by the `BR-n` number the index gives them; never renumber.
Write the contract as checkable statements. Mark a line `unverified` when the
code does not show it holding, and list it in `PLAN.md`.

---

```markdown
---
covers:
  - <path/or/glob/**>
commit: <short SHA or unknown>
---

# Module: <name>

Risk: <high | medium | low> · Owner: <owner or unknown>

## Entry points

| Entry point | Method / trigger | Caller or role | Guard |
| --- | --- | --- | --- |
| <route or handler> | <GET /path> | <role> | <middleware or "none"> |

## Business rules

- **BR-<n>**: <rule, as in the index>. Enforced at: `<file>:<line>` or "not found".

## Data and sensitivity

| Data | Where | Sensitivity |
| --- | --- | --- |
| <data> | <model, field or file> | <high / medium / low> |

## depends_on

- <module or external service>: <what this module relies on it for>

## Contract

### ASSUMES

- <what must already hold when this module is called, e.g. "caller passed requireAuth"> (<verified at file:line | unverified>)

### GUARANTEES

- <what this module ensures for its callers, e.g. "returns only the caller's own orders"> (<verified at file:line | unverified>)

## Open questions

- <anything the interview could not settle>
```
