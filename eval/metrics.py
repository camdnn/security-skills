"""Score matcher results and aggregate them across evaluation trials.

The matcher deliberately knows nothing about reporting.  This module turns its
classification into counts, rates, fixture-pass results, and attribution data
without re-inspecting files or trusting additional model output.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Hashable, Iterable
from dataclasses import dataclass
from math import sqrt
from pathlib import Path
from typing import Any

from eval.matcher import MatchResult

CWE_FAMILIES_PATH = Path(__file__).with_name("cwe_families.json")


@dataclass(frozen=True)
class Counts:
    """The mutually exclusive scoring counts for one slice of an evaluation."""

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    duplicates: int = 0

    def __add__(self, other: Counts) -> Counts:
        return Counts(
            self.true_positives + other.true_positives,
            self.false_positives + other.false_positives,
            self.false_negatives + other.false_negatives,
            self.duplicates + other.duplicates,
        )


@dataclass(frozen=True)
class Rates:
    """Precision, recall, and F1 derived from a set of counts.

    A rate with no denominator is ``None`` rather than zero.  In particular, a
    safe target with no findings has null *per-target* precision; it therefore
    cannot penalize a later micro-average across targets.
    """

    precision: float | None
    recall: float | None
    f1: float | None


@dataclass(frozen=True)
class TrialMetrics:
    """Metrics for one target/mode/run matcher result."""

    counts: Counts
    rates: Rates
    fixture_passed: bool
    matched_truth: frozenset[Hashable]
    truth_entries: frozenset[Hashable]
    breakdowns: dict[str, dict[str, Counts]]
    run_id: Hashable = 0


@dataclass(frozen=True)
class AggregateMetrics:
    """Micro metrics for every run plus distribution and stable-recall data."""

    per_run: dict[Hashable, Rates]
    micro_counts: Counts
    micro_rates: Rates
    mean: Rates
    minimum: Rates
    standard_deviation: Rates
    stable_recall: float | None
    fixture_passes: int
    fixture_trials: int
    breakdowns: dict[str, dict[str, Counts]]


def rates_for(counts: Counts) -> Rates:
    """Calculate rates without converting a zero denominator into a false zero."""

    precision_denominator = counts.true_positives + counts.false_positives
    recall_denominator = counts.true_positives + counts.false_negatives
    precision = counts.true_positives / precision_denominator if precision_denominator else None
    recall = counts.true_positives / recall_denominator if recall_denominator else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    return Rates(precision, recall, f1)


def score_trial(
    result: MatchResult,
    ground_truth: dict[str, Any],
    *,
    target_id: Hashable = "target",
    mode: str | None = None,
    run_id: Hashable = 0,
) -> TrialMetrics:
    """Score one matcher result and attribute it to the required dimensions.

    False negatives are attributed to the owning check for their CWE family,
    rather than to any finding, because no finding exists for an FN.
    """

    registry = json.loads(CWE_FAMILIES_PATH.read_text())
    families = registry["cwe_to_family"]
    owners = registry["families"]
    entries = ground_truth.get("truth", [])
    entry_keys = {id(entry): (target_id, entry["id"]) for entry in entries}

    counts = Counts(
        true_positives=len(result.matches),
        false_positives=len(result.false_positives),
        false_negatives=len(result.false_negatives),
        duplicates=len(result.duplicates),
    )
    matched_truth = frozenset(entry_keys[id(match.entry)] for match in result.matches)
    truth_entries = frozenset(entry_keys[id(entry)] for entry in entries)
    breakdowns: defaultdict[str, defaultdict[str, Counts]] = defaultdict(lambda: defaultdict(Counts))

    for match in result.matches:
        _add(breakdowns, "skill", match.finding["skill"], true_positives=1)
        _add(breakdowns, "cwe_family", families.get(match.finding["cwe"], "unknown"), true_positives=1)
        _add(breakdowns, "requires_context", str(bool(match.entry["requires_context"])).lower(), true_positives=1)
    for false_positive in result.false_positives:
        _add(breakdowns, "skill", false_positive.finding["skill"], false_positives=1)
        _add(breakdowns, "cwe_family", families.get(false_positive.finding["cwe"], "unknown"), false_positives=1)
    for entry in result.false_negatives:
        family = families[entry["cwe"]]
        _add(breakdowns, "skill", owners[family], false_negatives=1)
        _add(breakdowns, "cwe_family", family, false_negatives=1)
        _add(breakdowns, "requires_context", str(bool(entry["requires_context"])).lower(), false_negatives=1)
    if mode is not None:
        _add_counts(breakdowns, "mode", mode, counts)

    # A safe fixture has no truth entries; its pass condition is solely that no
    # must-not-find rule was hit.  A vulnerable fixture must match every entry.
    safe = not entries
    fixture_passed = (
        not any(fp.must_not_find_rule is not None for fp in result.false_positives)
        if safe
        else not result.false_negatives
    )
    return TrialMetrics(
        counts=counts,
        rates=rates_for(counts),
        fixture_passed=fixture_passed,
        matched_truth=matched_truth,
        truth_entries=truth_entries,
        breakdowns={dimension: dict(values) for dimension, values in breakdowns.items()},
        run_id=run_id,
    )


def aggregate_trials(trials: Iterable[TrialMetrics]) -> AggregateMetrics:
    """Micro-average target results and summarize their per-run distribution.

    Trials sharing a ``run_id`` are first summed, so every target contributes to
    that run's micro score.  Standard deviation is population standard deviation
    because the configured set of trials is the entire evaluation run, not a
    sample from an unknown set.
    """

    trials = list(trials)
    counts_by_run: defaultdict[Hashable, Counts] = defaultdict(Counts)
    all_counts = Counts()
    breakdowns: defaultdict[str, defaultdict[str, Counts]] = defaultdict(lambda: defaultdict(Counts))
    appearances: defaultdict[Hashable, int] = defaultdict(int)
    matches: defaultdict[Hashable, int] = defaultdict(int)
    for trial in trials:
        counts_by_run[trial.run_id] = counts_by_run[trial.run_id] + trial.counts
        all_counts = all_counts + trial.counts
        for dimension, values in trial.breakdowns.items():
            for value, counts in values.items():
                _add_counts(breakdowns, dimension, value, counts)
        for entry in trial.truth_entries:
            appearances[entry] += 1
        for entry in trial.matched_truth:
            matches[entry] += 1

    per_run = {run_id: rates_for(counts) for run_id, counts in counts_by_run.items()}
    rate_sets = list(per_run.values())
    stable_entries = sum(matches[entry] == count for entry, count in appearances.items())
    stable_recall = stable_entries / len(appearances) if appearances else None
    return AggregateMetrics(
        per_run=per_run,
        micro_counts=all_counts,
        micro_rates=rates_for(all_counts),
        mean=_summary_rates(rate_sets, "mean"),
        minimum=_summary_rates(rate_sets, "min"),
        standard_deviation=_summary_rates(rate_sets, "stddev"),
        stable_recall=stable_recall,
        fixture_passes=sum(trial.fixture_passed for trial in trials),
        fixture_trials=len(trials),
        breakdowns={dimension: dict(values) for dimension, values in breakdowns.items()},
    )


def _add(bucket: Any, dimension: str, value: str, **increments: int) -> None:
    current = bucket[dimension][value]
    bucket[dimension][value] = Counts(
        current.true_positives + increments.get("true_positives", 0),
        current.false_positives + increments.get("false_positives", 0),
        current.false_negatives + increments.get("false_negatives", 0),
        current.duplicates + increments.get("duplicates", 0),
    )


def _add_counts(bucket: Any, dimension: str, value: str, counts: Counts) -> None:
    bucket[dimension][value] = bucket[dimension][value] + counts


def _summary_rates(rates: list[Rates], statistic: str) -> Rates:
    return Rates(
        _summary([rate.precision for rate in rates], statistic),
        _summary([rate.recall for rate in rates], statistic),
        _summary([rate.f1 for rate in rates], statistic),
    )


def _summary(values: list[float | None], statistic: str) -> float | None:
    values = [value for value in values if value is not None]
    if not values:
        return None
    if statistic == "mean":
        return sum(values) / len(values)
    if statistic == "min":
        return min(values)
    mean = sum(values) / len(values)
    return sqrt(sum((value - mean) ** 2 for value in values) / len(values))
