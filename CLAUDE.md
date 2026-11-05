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
`--sandbox workspace-write`, `--cd`, and a pinned model. `codex exec` is
non-interactive with that sandbox; `--approve-for-me` cannot be combined with it.
These flags were checked against the installed Codex CLI `0.166.0` on
2026-11-05. The current ChatGPT-account evaluator pin is `gpt-5.6-terra`,
verified by a successful local inference; re-check both before changing the
runner. Claude Code was not installed in this environment, so its version must
be captured before a live Claude trial.

### Local Python

Run `pytest`, `ruff` and `mypy` from `.venv/bin/`. If `.venv/` is missing,
create it with the pinned Python 3.11 (`.python-version`; install it with
`uv python install 3.11` or `pyenv install 3.11`), then run
`.venv/bin/pip install -e '.[dev]'`.
