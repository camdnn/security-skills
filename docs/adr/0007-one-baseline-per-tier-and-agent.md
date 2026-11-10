# One baseline per tier and agent

Each agent keeps its own baseline for each tier, in `eval/baselines/claude.json` and `eval/baselines/codex.json`. An eval run is compared only against the baseline for its own tier and agent, and `accept-baseline` writes to the file named by the run's own agent. This replaces ADR-0004's single baseline per tier. The two developers work on different agents: one has only a ChatGPT login, so runs Codex, and the other runs Claude. With one baseline per tier, whoever's agent didn't produce it would have every regression check skipped, which is no regression check at all for half the skill changes.

We rejected comparing a run against the other agent's baseline, because the gap between agents would be read as a skill regression or improvement. We chose one file per agent over one file keyed by tier and agent, so each developer usually commits only their own file and baseline commits don't conflict.

## Consequences

The two baselines are accepted independently, each in its own commit, and need not come from the same code: a gap between them is not a measurement of the agents. A `SKILL.md` change is evaluated on its author's agent, and the other agent's baseline catches up the next time it is accepted. Each entry still records its agent, and the checker refuses a file whose entry names another agent than the file, so a copied or hand-edited baseline is caught (§8 item 6). `accept-baseline` takes no `--agent` flag, and it refuses agent names other than `claude` and `codex`, because the name read from `metrics.json` chooses the path it writes.
