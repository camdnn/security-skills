"""Metrics tests for issue #5's micro-averaging and stability contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval.matcher import match
from eval.metrics import aggregate_trials, score_trial

DATA = Path(__file__).parent / "data"
TARGET_ROOT = "/target"


def load(name: str) -> dict:
    return json.loads((DATA / name).read_text())


def finding(**changes: object) -> dict:
    return load("finding-example.json") | {
        "skill": "injection-check",
        "cwe": "CWE-89",
        "file": "routes/search.ts",
        "line": 40,
        "end_line": 48,
    } | changes


def test_empty_findings_are_all_false_negatives_with_null_precision() -> None:
    truth = load("matcher-truth.json")
    metrics = score_trial(match([], truth, TARGET_ROOT), truth)

    assert metrics.counts.true_positives == 0
    assert metrics.counts.false_negatives == 2
    assert metrics.rates.precision is None
    assert metrics.rates.recall == 0
    assert metrics.rates.f1 is None


def test_clean_safe_fixture_passes_and_does_not_lower_micro_precision() -> None:
    safe_truth = {"truth": [], "must_not_find": [{"file": "safe.ts", "cwe_family": "injection"}]}
    vulnerable_truth = load("matcher-truth.json")
    safe = score_trial(match([], safe_truth, TARGET_ROOT), safe_truth, target_id="safe")
    vulnerable = score_trial(
        match([finding()], vulnerable_truth, TARGET_ROOT), vulnerable_truth, target_id="vulnerable"
    )

    aggregate = aggregate_trials([safe, vulnerable])

    assert safe.fixture_passed
    assert aggregate.micro_rates.precision == 1
    assert aggregate.micro_counts.false_positives == 0


def test_stable_recall_and_population_standard_deviation_are_correct() -> None:
    truth = load("matcher-truth.json")
    all_found = [finding(), finding(cwe="CWE-639", file="routes/order.ts", line=10, end_line=12, skill="access-control-check")]
    trials = [
        score_trial(match([], truth, TARGET_ROOT), truth, run_id=1),
        score_trial(match(all_found[:1], truth, TARGET_ROOT), truth, run_id=2),
        score_trial(match(all_found, truth, TARGET_ROOT), truth, run_id=3),
    ]

    aggregate = aggregate_trials(trials)

    assert aggregate.stable_recall == 0
    assert aggregate.mean.recall == pytest.approx(0.5)
    assert aggregate.minimum.recall == 0
    assert aggregate.standard_deviation.recall == pytest.approx((1 / 6) ** 0.5)


def test_breakdowns_attribute_false_negatives_to_family_owner() -> None:
    truth = load("matcher-truth.json")
    metrics = score_trial(match([], truth, TARGET_ROOT), truth, mode="context")

    assert metrics.breakdowns["skill"]["injection-check"].false_negatives == 1
    assert metrics.breakdowns["skill"]["access-control-check"].false_negatives == 1
    assert metrics.breakdowns["requires_context"]["true"].false_negatives == 1
    assert metrics.breakdowns["mode"]["context"].false_negatives == 2


def test_run_summaries_skip_undefined_rates() -> None:
    truth = load("matcher-truth.json")
    trials = [
        score_trial(match([], truth, TARGET_ROOT), truth, run_id=1),
        score_trial(match([finding()], truth, TARGET_ROOT), truth, run_id=2),
    ]

    aggregate = aggregate_trials(trials)

    assert aggregate.per_run[1].precision is None
    assert aggregate.mean.precision == 1
    assert aggregate.minimum.precision == 1
    assert aggregate.standard_deviation.precision == 0
    assert aggregate_trials(trials[:1]).mean.precision is None
