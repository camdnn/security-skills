"""Regression gates, baseline acceptance, and report persistence for issue #6."""

from __future__ import annotations

import json
import sys
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


def run(
    *,
    mean_f1: float = 0.8,
    skipped: bool = False,
    fixture: FixturePasses | None = None,
    agent: str = "claude",
    replay: bool = False,
) -> EvaluationRun:
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
        agent=agent,
        metrics=metrics,
        fixture_passes={"sql-injection": fixture or FixturePasses(3, 3)},
        failed_trials=[],
        skipped_trials=[{"id": "trial-3", "reason": "usage limit"}] if skipped else [],
        false_negatives=[{"id": "FN-1", "evidence": "missed sink"}],
        false_positives=[{"id": "FP-1", "evidence": "safe query"}],
        warnings=[],
        tokens=42,
        replay=replay,
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


def test_comparing_against_another_agents_baseline_is_an_error() -> None:
    with pytest.raises(ValueError, match="codex.*claude"):
        evaluate_regression(run(mean_f1=0), baseline(agent="codex"))


def test_write_results_writes_markdown_and_json(tmp_path: Path) -> None:
    result = write_results(run(), tmp_path, baselines_dir=tmp_path / "baselines")

    assert result.exit_code == EXIT_OK
    assert (tmp_path / "metrics.json").exists()
    report = (tmp_path / "report.md").read_text()
    assert "## Summary" in report
    assert "## Tokens" in report
    assert "missed sink" in report


def test_metrics_records_whether_an_eval_run_was_replayed(tmp_path: Path) -> None:
    write_results(run(replay=True), tmp_path / "replay")
    write_results(run(), tmp_path / "live")

    assert json.loads((tmp_path / "replay" / "metrics.json").read_text())["replay"] is True
    assert json.loads((tmp_path / "live" / "metrics.json").read_text())["replay"] is False


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
    write_results(report, tmp_path, baselines_dir=tmp_path / "baselines")

    with pytest.raises(ValueError, match=message):
        accept_baseline(tmp_path, baselines_dir=tmp_path / "baselines")


def test_accept_baseline_refuses_a_replay_eval_run_without_changing_baselines(tmp_path: Path) -> None:
    baselines = tmp_path / "baselines"
    write_baseline_file(baselines, "claude", baseline())
    before = (baselines / "claude.json").read_text()
    report_dir = tmp_path / "results"
    write_results(run(replay=True), report_dir, baselines_dir=baselines)

    with pytest.raises(ValueError, match="baseline must come from live trials"):
        accept_baseline(report_dir, baselines_dir=baselines)

    assert (baselines / "claude.json").read_text() == before


def test_accept_baseline_cli_refuses_a_replay_eval_run_with_exit_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from eval import __main__

    report_dir = tmp_path / "results"
    write_results(run(replay=True), report_dir)
    monkeypatch.setattr(
        __main__, "accept_baseline", lambda path: accept_baseline(path, baselines_dir=tmp_path / "baselines")
    )
    monkeypatch.setattr(sys, "argv", ["python -m eval", "accept-baseline", str(report_dir)])

    assert __main__.main() == 1
    assert "baseline must come from live trials" in capsys.readouterr().out


def test_accept_baseline_writes_the_runs_agent_file_keyed_by_tier(tmp_path: Path) -> None:
    baselines = tmp_path / "baselines"
    report_dir = tmp_path / "results"
    write_results(run(agent="codex"), report_dir, baselines_dir=baselines)

    accept_baseline(report_dir, baselines_dir=baselines)

    saved = json.loads((baselines / "codex.json").read_text())
    assert saved["fast"]["agent"] == "codex"
    assert saved["fast"]["mean_f1"] == 0.8
    assert not (baselines / "claude.json").exists()


def write_baseline_file(baselines: Path, agent: str, entry: dict) -> None:
    baselines.mkdir(parents=True, exist_ok=True)
    (baselines / f"{agent}.json").write_text(json.dumps({"fast": entry}))


def test_run_is_compared_against_its_own_agents_baseline(tmp_path: Path) -> None:
    baselines = tmp_path / "baselines"
    write_baseline_file(baselines, "claude", baseline(f1=0.5, agent="claude"))
    write_baseline_file(baselines, "codex", baseline(f1=0.9, agent="codex"))

    result = write_results(run(mean_f1=0.7, agent="codex"), tmp_path / "results", baselines_dir=baselines)

    assert result.exit_code == EXIT_REGRESSION
    assert "mean F1 dropped by 0.200" in result.reasons[0]


def test_run_without_a_baseline_for_its_agent_is_not_compared(tmp_path: Path) -> None:
    baselines = tmp_path / "baselines"
    write_baseline_file(baselines, "claude", baseline(f1=0.9, agent="claude"))

    result = write_results(run(mean_f1=0.1, agent="codex"), tmp_path / "results", baselines_dir=baselines)

    assert result.exit_code == EXIT_OK
    assert result.reasons == ["no baseline for this tier and agent"]


def test_baseline_file_whose_entry_names_another_agent_is_refused(tmp_path: Path) -> None:
    baselines = tmp_path / "baselines"
    write_baseline_file(baselines, "codex", baseline(agent="claude"))

    with pytest.raises(ValueError, match="codex.json.*claude"):
        write_results(run(agent="codex"), tmp_path / "results", baselines_dir=baselines)


def test_accept_baseline_refuses_an_unknown_agent(tmp_path: Path) -> None:
    report_dir = tmp_path / "results"
    write_results(run(agent="../escape"), report_dir, check_baseline=False)

    with pytest.raises(ValueError, match="unknown agent"):
        accept_baseline(report_dir, baselines_dir=tmp_path / "baselines")
    assert not (tmp_path / "escape.json").exists()


def test_report_names_the_baseline_it_compared_against(tmp_path: Path) -> None:
    baselines = tmp_path / "baselines"
    write_baseline_file(baselines, "codex", baseline(agent="codex"))

    write_results(run(agent="codex"), tmp_path / "with", baselines_dir=baselines)
    write_results(run(agent="claude"), tmp_path / "without", baselines_dir=baselines)

    assert "Baseline: codex / fast." in (tmp_path / "with" / "report.md").read_text()
    assert "Baseline: none for claude / fast." in (tmp_path / "without" / "report.md").read_text()


def test_report_says_when_the_baseline_check_was_disabled(tmp_path: Path) -> None:
    baselines = tmp_path / "baselines"
    write_baseline_file(baselines, "codex", baseline(agent="codex"))

    write_results(run(agent="codex"), tmp_path / "results", baselines_dir=baselines, check_baseline=False)

    report = (tmp_path / "results" / "report.md").read_text()
    assert "Baseline: check disabled." in report
    assert "none for" not in report
