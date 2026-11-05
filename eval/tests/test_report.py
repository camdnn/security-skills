"""Regression gates, baseline acceptance, and report persistence for issue #6."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval.metrics import AggregateMetrics, Counts, Rates
from eval.report import (
    EXIT_INCOMPLETE,
    EXIT_OK,
    EXIT_REGRESSION,
    EvaluationRun,
    FixturePasses,
    accept_baseline,
    evaluate_regression,
    write_results,
)


def run(*, mean_f1: float = 0.8, skipped: bool = False, fixture: FixturePasses | None = None) -> EvaluationRun:
    rates = Rates(0.8, 0.8, mean_f1)
    metrics = AggregateMetrics(
        per_run={1: rates},
        micro_counts=Counts(8, 2, 2),
        micro_rates=rates,
        mean=rates,
        minimum=rates,
        standard_deviation=Rates(0, 0, 0),
        stable_recall=0.8,
        fixture_passes=fixture.passed if fixture else 3,
        fixture_trials=fixture.trials if fixture else 3,
        breakdowns={},
    )
    return EvaluationRun(
        tier="fast",
        agent="claude",
        metrics=metrics,
        fixture_passes={"sql-injection": fixture or FixturePasses(3, 3)},
        failed_trials=[],
        skipped_trials=[{"id": "trial-3", "reason": "usage limit"}] if skipped else [],
        false_negatives=[{"id": "FN-1", "evidence": "missed sink"}],
        false_positives=[{"id": "FP-1", "evidence": "safe query"}],
        tokens=42,
    )


def baseline(*, f1: float = 0.8, agent: str = "claude", fixture: FixturePasses | None = None) -> dict:
    passes = fixture or FixturePasses(2, 3)
    return {"agent": agent, "mean_f1": f1, "fixture_passes": {"sql-injection": {"passed": passes.passed, "trials": passes.trials}}}


def test_exit_zero_when_no_regression() -> None:
    assert evaluate_regression(run(), baseline()).exit_code == EXIT_OK


def test_exit_one_for_mean_f1_regression() -> None:
    result = evaluate_regression(run(mean_f1=0.74), baseline(f1=0.8), threshold=0.05)

    assert result.exit_code == EXIT_REGRESSION
    assert "mean F1 dropped" in result.reasons[0]


def test_exit_one_for_fixture_pass_regression() -> None:
    result = evaluate_regression(run(fixture=FixturePasses(0, 3)), baseline())

    assert result.exit_code == EXIT_REGRESSION
    assert "fixture sql-injection" in result.reasons[0]


def test_exit_two_for_incomplete_run_without_baseline_comparison() -> None:
    result = evaluate_regression(run(skipped=True, mean_f1=0), baseline())

    assert result.exit_code == EXIT_INCOMPLETE
    assert "not baseline-compared" in result.reasons[0]


def test_agent_mismatch_skips_regression_check() -> None:
    result = evaluate_regression(run(mean_f1=0), baseline(agent="codex"))

    assert result.exit_code == EXIT_OK
    assert result.reasons == ["baseline agent mismatch; regression check skipped"]


def test_write_results_writes_markdown_and_json(tmp_path: Path) -> None:
    result = write_results(run(), tmp_path, baseline_path=tmp_path / "baseline.json")

    assert result.exit_code == EXIT_OK
    assert (tmp_path / "metrics.json").exists()
    report = (tmp_path / "report.md").read_text()
    assert "## Summary" in report
    assert "## Tokens" in report
    assert "missed sink" in report


@pytest.mark.parametrize(
    ("failed", "skipped", "message"),
    [
        pytest.param([{"id": "bad", "reason": "schema-invalid"}], [], "failed trials", id="failed"),
        pytest.param([], [{"id": "missing", "reason": "usage limit"}], "incomplete", id="incomplete"),
    ],
)
def test_accept_baseline_refuses_failed_and_incomplete_runs(
    tmp_path: Path, failed: list[dict], skipped: list[dict], message: str
) -> None:
    report = run()
    report = EvaluationRun(**{**report.__dict__, "failed_trials": failed, "skipped_trials": skipped})
    write_results(report, tmp_path, baseline_path=tmp_path / "baseline.json")

    with pytest.raises(ValueError, match=message):
        accept_baseline(tmp_path, baseline_path=tmp_path / "baseline.json")


def test_accept_baseline_keys_data_by_tier_and_records_agent(tmp_path: Path) -> None:
    report_dir = tmp_path / "results"
    write_results(run(), report_dir, baseline_path=tmp_path / "baseline.json")

    accept_baseline(report_dir, baseline_path=tmp_path / "baseline.json")

    saved = json.loads((tmp_path / "baseline.json").read_text())
    assert saved["fast"]["agent"] == "claude"
    assert saved["fast"]["mean_f1"] == 0.8
