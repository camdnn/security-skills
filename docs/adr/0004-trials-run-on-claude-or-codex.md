# Trials can run on Claude Code or Codex

The checker can run trials on either Claude Code or Codex (`--agent claude|codex`). Fast-tier trials default to Claude, and full-tier trials default to Codex. Full-tier runs (Juice Shop and NodeGoat in both modes) are the most expensive, and running them on the ChatGPT plan keeps them out of the Claude Pro usage window that development also needs. Skills therefore use only the shared Agent Skills (`SKILL.md`) standard: Claude-only features such as subagent fan-out are optional, and the runner starts the scan without relying on the `/analyzer:` prefix. Trials always run on subscription logins. The runner refuses to start if `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is set.

## Consequences

Full-tier numbers describe the skills running under Codex, not what a Claude user gets. The production-ready targets are tracked on Codex full-tier runs, and one Claude full-tier eval run in week 6 confirms them. Each tier has one baseline that records its agent. An eval run on a different agent skips the regression check and says why, instead of reporting a false regression.
