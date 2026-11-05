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

### Evaluator CLI assumptions

The evaluator uses Claude Code's non-interactive `-p`, `--output-format json`,
`--model`, and `--allowedTools` flags. Codex trials use `codex exec` with
`--sandbox workspace-write`, `--ask-for-approval never`, `--cd`, and a pinned
model. These flags were checked against the official CLI references on
2026-11-05; re-check them before changing the runner. Development verification
used Codex CLI `0.166.0`; Claude Code was not installed in this environment, so
its version must be captured before a live Claude trial.

### Local Python

Use the repository's pinned Python 3.11 interpreter for local evaluation work.
Install it with `uv python install 3.11` or `pyenv install 3.11`; both tools
honor `.python-version` when creating or selecting an environment.
