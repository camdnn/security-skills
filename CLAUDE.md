# security-skills

Claude MD files to go through codebase and dynamically detect security vulnerabilities based on the codebase context.

- **Spec**: `docs/tickets/TICKET-001.md` (long). Issues cite its `§` numbers: list headings with `grep -n '^#'` and read the cited sections, plus §0, which holds the project rules for all work.

## Checker

`python -m eval` scores the skills against ground truth; `--help` on each
subcommand lists its flags.

- **Replay first.** `run --tier fast --replay <dir>` scores recorded findings
  with no agent and no usage quota. Live trials (`run --tier fast|full`) spend
  subscription usage, so run them deliberately (TICKET-001 §8).
- **`run` exit codes:** `0` ok, `1` regression or error, `2` incomplete eval
  run (resume it with `--resume <results-dir>`) or a bad flag.
- **After changing any `SKILL.md`**, run the fast tier and put the metrics diff
  in your summary (§0 rule 7).
- **Ground truth changes only when a human says the ground truth itself is
  wrong.** When a test or metric disagrees with an `expected.json`, report it
  and ask (§0 rule 2). CI fails a PR that touches `expected.json` unless a
  human adds the `ground-truth-change` label, so ground truth reaches `main`
  only through a PR from its own branch. `python -m eval check-truth` must pass.
- **Baseline changes only through `accept-baseline <results-dir>`.** There is
  one baseline per agent, `eval/baselines/claude.json` and
  `eval/baselines/codex.json`, each keyed by tier (ADR-0007). The run's agent
  picks the file. Commit each one on its own, with a message that names the
  agent and says why (§8 item 7). Evaluate a `SKILL.md` change on your own
  agent and name it in the metrics diff.
- **A sudden perfect score is suspect.** Check that nothing touched an
  `expected.json`, a fixture, or a file in `eval/baselines/` (§8 item 6).

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues on `camdnn/security-skills` via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

### Evaluator CLI assumptions

The evaluator uses Claude Code's non-interactive `-p`, `--output-format json`,
`--model`, `--plugin-dir`, `--allowedTools` and `--disallowedTools` flags, and
isolates trials with `--strict-mcp-config` and `--setting-sources project`
(ADR-0002). Claude trials invoke `/analyzer:security-scan` (ADR-0003). These
flags were checked against `claude --help` for Claude Code `2.1.322` on
2026-11-10. The Claude evaluator pin is `claude-sonnet-5-5`, verified by a
successful local inference that day. Codex trials use `codex exec` with
`--sandbox workspace-write`, `--cd`, and a pinned model. `codex exec` is
non-interactive with that sandbox; `--approve-for-me` cannot be combined with it.
These flags were checked against the installed Codex CLI `0.166.0` on
2026-11-05. The current ChatGPT-account evaluator pin is `gpt-5.6-terra`,
verified by a successful local inference; re-check both before changing the
runner.

### Local Python

Run `pytest`, `ruff` and `mypy eval` from `.venv/bin/`. If `.venv/` is missing,
create it with the pinned Python 3.11 (`.python-version`; install it with
`uv python install 3.11` or `pyenv install 3.11`), then run
`.venv/bin/pip install -e '.[dev]'`.
