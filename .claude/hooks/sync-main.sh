#!/bin/sh
# SessionStart: fast-forward local main to origin/main so agents never
# branch from or compare against a stale main. Never rewrites history:
# updates are fast-forward only, and a dirty or diverged main is left alone.
# Stdout reaches the agent's context, so it only speaks when main is stale.
cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
git fetch -q origin main 2>/dev/null || exit 0
if [ "$(git branch --show-current)" = main ]; then
  [ -z "$(git status --porcelain)" ] && git merge -q --ff-only origin/main 2>/dev/null
else
  git fetch -q origin main:main 2>/dev/null
fi
if [ "$(git rev-parse main 2>/dev/null)" != "$(git rev-parse origin/main)" ]; then
  echo "Local main differs from origin/main and could not be fast-forwarded; branch from and diff against origin/main."
fi
exit 0
