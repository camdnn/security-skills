# security-skills

Claude MD files to go through codebase and dynamically detect security vulnerabilities based on the codebase context.

- **Spec**: `docs/tickets/TICKET-001.md` (long). Issues cite its `§` numbers: list headings with `grep -n '^#'` and read the cited sections, plus §0, which holds the project rules for all work.

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues on `camdnn/security-skills` via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
