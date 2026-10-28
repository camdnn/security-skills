# The fast tier runs security-scan, not individual checks

Fast-tier trials run `/analyzer:security-scan` on each fixture (code-only mode, or context mode for context fixtures). They don't call `*-check` skills directly. Calling the checks directly would be cheaper and better isolated, but it would measure a path users never take, and orchestrator bugs (fan-out, merge, dedupe) would go unseen until the expensive full tier. `--skill` narrows which fixtures run, not what gets invoked.
