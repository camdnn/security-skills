# security-skills

Claude MD files to go through codebase and dynamically detect security vulnerabilities based on the codebase context.

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues on `camdnn/security-skills` via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
