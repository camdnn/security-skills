"""A replay eval run over recorded findings gives the saved metrics (issue #75).

`data/replay/` holds one recorded findings file per fixture, chosen to give
matches, a must-not-find false positive and false negatives. `data/replay-metrics.json`
is the `metrics.json` a replay eval run of them produces. Change the saved file
only when scoring or ground truth is meant to change, and say why in the commit.
A new fixture needs its own recorded findings under `data/replay/`.
"""

import json
from pathlib import Path

from eval.runner import RunOptions, run

DATA = Path(__file__).parent / "data"


def test_replay_eval_run_over_recorded_findings_gives_the_saved_metrics(tmp_path: Path):
    results, _ = run(
        RunOptions(tier="fast", runs=1, replay_dir=DATA / "replay", results_dir=tmp_path, baseline_check=False)
    )

    assert json.loads((results / "metrics.json").read_text()) == json.loads((DATA / "replay-metrics.json").read_text())
