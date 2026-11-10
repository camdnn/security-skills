# Security scan report

## Scope

- Target: `<target>`
- Mode: `<context|code-only>`
- Checks run: `<check names>`
- Files and entry points reviewed: `<paths>`

## Stale-context warnings

`<none, or each stale module and changed covered path>`

## Ranked findings

For each finding, in descending DREAD score order:

### SEC-NNNN — `<title>`

- DREAD: `<score>/5`
- Confidence: `<high|medium|low>`
- Location: `<file>:<line>-<end_line>`
- Why it matters: `<why>`
- Recommended fix: `<fix>`

## Limitations

- `<unscanned paths, unavailable context, or other material limits>`
- A clean scan is not a guarantee that the target has no vulnerabilities.
