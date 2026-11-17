"""The configured trial caps fit a complete eval run (TICKET-001 §4 Q10, issue #51).

A cap below one complete run makes every such run incomplete, and `--resume`
can't finish it, so no baseline can ever be accepted.
"""

from eval.runner import REPO_ROOT, discover_targets, load_config, modes_for_target


def test_fast_trial_cap_covers_a_complete_fast_tier_eval_run():
    tier = "fast"
    config = load_config()
    trials = sum(
        len(modes_for_target(target, tier, None)) * int(config["trials_per_target"])
        for target in discover_targets(REPO_ROOT, tier, None)
    )

    assert int(config["max_trials"][tier]) >= trials
