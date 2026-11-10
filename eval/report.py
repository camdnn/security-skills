"""Persist evaluation reports, compare baselines, and choose process exit codes."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final, Literal

import yaml

from eval.metrics import AggregateMetrics, Counts, Rates

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINES_DIR = Path(__file__).with_name("baselines")
BASELINE_AGENTS = ("claude", "codex")
CONFIG_PATH = Path(__file__).with_name("config.yaml")
EXIT_OK: Final = 0
EXIT_REGRESSION: Final = 1
EXIT_INCOMPLETE: Final = 2


@dataclass(frozen=True)
class FixturePasses:
    """The number of passing trials for one fixture."""

    passed: int
    trials: int


@dataclass(frozen=True)
class EvaluationRun:
    """All data needed to render and gate one complete checker invocation."""

    tier: str
    agent: str
    metrics: AggregateMetrics
    fixture_passes: dict[str, FixturePasses]
    failed_trials: list[dict[str, Any]]
    skipped_trials: list[dict[str, Any]]
    false_negatives: list[dict[str, Any]]
    false_positives: list[dict[str, Any]]
    warnings: list[dict[str, Any]]
    tokens: int | None = None


@dataclass(frozen=True)
class RegressionResult:
    """Whether a run may proceed, and the human-readable reasons why."""

    exit_code: Literal[0, 1, 2]
    reasons: list[str]


def load_regression_threshold(config_path: Path | str = CONFIG_PATH) -> float:
    """Load the configured mean-F1 tolerance."""

    config = yaml.safe_load(Path(config_path).read_text()) or {}
    return float(config.get("regression_f1_threshold", 0.05))


def evaluate_regression(
    run: EvaluationRun,
    baseline: dict[str, Any] | None,
    *,
    threshold: float = 0.05,
) -> RegressionResult:
    """Apply the locked regression rules, with incomplete runs taking priority."""

    if run.skipped_trials:
        return RegressionResult(EXIT_INCOMPLETE, ["incomplete eval run: skipped trials are not baseline-compared"])
    if baseline is None:
        return RegressionResult(EXIT_OK, ["no baseline for this tier and agent"])
    if baseline.get("agent") != run.agent:
        raise ValueError(f"baseline recorded by {baseline.get('agent')!r} cannot judge a {run.agent!r} run (ADR-0007)")

    reasons: list[str] = []
    baseline_f1 = baseline.get("mean_f1")
    current_f1 = run.metrics.mean.f1
    if baseline_f1 is not None and current_f1 is not None and baseline_f1 - current_f1 > threshold:
        reasons.append(
            f"mean F1 dropped by {baseline_f1 - current_f1:.3f}, exceeding threshold {threshold:.3f}"
        )
    for fixture, old in baseline.get("fixture_passes", {}).items():
        previous = _fixture_passes(old)
        current = run.fixture_passes.get(fixture)
        if previous.passed >= 2 and previous.trials >= 3 and current and current.passed == 0 and current.trials >= 3:
            reasons.append(f"fixture {fixture} passed {previous.passed}/{previous.trials} in baseline and 0/{current.trials} now")
    return RegressionResult(EXIT_REGRESSION if reasons else EXIT_OK, reasons or ["no regression detected"])


def write_results(
    run: EvaluationRun,
    results_dir: Path | str,
    *,
    baselines_dir: Path | str = BASELINES_DIR,
    threshold: float | None = None,
    check_baseline: bool = True,
) -> RegressionResult:
    """Write ``metrics.json`` and ``report.md``, returning the required exit code."""

    results_dir = Path(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    baseline = load_baseline(_baseline_file(baselines_dir, run.agent)).get(run.tier) if check_baseline else None
    result = evaluate_regression(run, baseline, threshold=load_regression_threshold() if threshold is None else threshold)
    if not check_baseline and result.exit_code != EXIT_INCOMPLETE:
        result = RegressionResult(EXIT_OK, ["baseline check disabled"])
    metrics_document = serialize_run(run, result)
    (results_dir / "metrics.json").write_text(json.dumps(metrics_document, indent=2, sort_keys=True) + "\n")
    (results_dir / "report.md").write_text(render_report(run, result, baseline, checked=check_baseline))
    return result


def accept_baseline(results_dir: Path | str, *, baselines_dir: Path | str = BASELINES_DIR) -> None:
    """Accept a sound, complete report as the baseline for its tier and agent.

    The run's own ``metrics.json`` names the agent, and so picks the file:
    there is deliberately no way to write one agent's numbers to another's file.

    Reports with skipped trials are incomplete.  Failed trials are also refused:
    a baseline is an affirmative quality decision, not merely an exit status.
    """

    metrics_path = Path(results_dir) / "metrics.json"
    try:
        document = json.loads(metrics_path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read metrics report: {error}") from error
    if document.get("skipped_trials"):
        raise ValueError("cannot accept baseline from an incomplete eval run")
    if document.get("failed_trials"):
        raise ValueError("cannot accept baseline from an eval run with failed trials")

    tier = document.get("tier")
    agent = document.get("agent")
    mean_f1 = document.get("metrics", {}).get("mean", {}).get("f1")
    if not isinstance(tier, str) or not isinstance(agent, str):
        raise TypeError("metrics report is missing tier or agent")
    new_entry = {"agent": agent, "mean_f1": mean_f1, "fixture_passes": document.get("fixture_passes", {})}
    path = _baseline_file(baselines_dir, agent)
    baselines = load_baseline(path)
    baselines[tier] = new_entry
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baselines, indent=2, sort_keys=True) + "\n")


def load_baseline(path: Path | str) -> dict[str, Any]:
    """Load one agent's tier-keyed baseline file; a missing file is an empty baseline.

    Every entry must record the agent the file is named after, so a copied or
    hand-edited file can't pass one agent's numbers off as another's.
    """

    path = Path(path)
    if not path.exists():
        return {}
    try:
        document = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read baseline: {error}") from error
    if not isinstance(document, dict):
        raise TypeError("baseline must be a JSON object keyed by tier")
    for tier, entry in document.items():
        recorded = entry.get("agent") if isinstance(entry, dict) else None
        if recorded != path.stem:
            raise ValueError(f"baseline {path.name} has a {tier} entry recorded by agent {recorded!r}")
    return document


def _baseline_file(baselines_dir: Path | str, agent: str) -> Path:
    if agent not in BASELINE_AGENTS:
        raise ValueError(f"unknown agent {agent!r}; baselines exist only for {', '.join(BASELINE_AGENTS)}")
    return Path(baselines_dir) / f"{agent}.json"


def serialize_run(run: EvaluationRun, result: RegressionResult) -> dict[str, Any]:
    """Return the stable, JSON-only report contract consumed by baseline acceptance."""

    return {
        "tier": run.tier,
        "agent": run.agent,
        "metrics": _json_value(run.metrics),
        "fixture_passes": _json_value(run.fixture_passes),
        "failed_trials": run.failed_trials,
        "skipped_trials": run.skipped_trials,
        "false_negatives": run.false_negatives,
        "false_positives": run.false_positives,
        "warnings": run.warnings,
        "tokens": run.tokens,
        "exit_code": result.exit_code,
        "regression_reasons": result.reasons,
    }


def render_report(
    run: EvaluationRun, result: RegressionResult, baseline: dict[str, Any] | None, *, checked: bool = True
) -> str:
    """Render the documented Markdown sections without requiring a template engine."""

    mean = run.metrics.mean
    baseline_f1 = baseline.get("mean_f1") if baseline else None
    diff = _difference(mean.f1, baseline_f1)
    lines = [
        "# Evaluation report",
        "",
        "## Summary",
        "",
        "| Metric | Mean | Minimum | Std-dev |",
        "| --- | ---: | ---: | ---: |",
        _rate_row("Precision", mean.precision, run.metrics.minimum.precision, run.metrics.standard_deviation.precision),
        _rate_row("Recall", mean.recall, run.metrics.minimum.recall, run.metrics.standard_deviation.recall),
        _rate_row("F1", mean.f1, run.metrics.minimum.f1, run.metrics.standard_deviation.f1),
        "",
        f"Stable recall: {_rate(run.metrics.stable_recall)}. Fixture passes: {run.metrics.fixture_passes}/{run.metrics.fixture_trials}.",
        "",
        "## Agent",
        "",
        run.agent,
        "",
        "## Baseline comparison",
        "",
        _baseline_line(run, baseline, checked=checked),
        "",
        f"Mean F1: {_rate(mean.f1)} ({diff}).",
        *[f"- {reason}" for reason in result.reasons],
        "",
        "## Top false negatives",
        "",
        *_evidence_lines(run.false_negatives),
        "",
        "## Top false positives",
        "",
        *_evidence_lines(run.false_positives),
        "",
        "## Warnings",
        "",
        *_warning_lines(run.warnings),
        "",
        "## Failed trials",
        "",
        *_trial_lines(run.failed_trials),
        "",
        "## Skipped trials",
        "",
        *_trial_lines(run.skipped_trials),
        "",
        "## Tokens",
        "",
        str(run.tokens) if run.tokens is not None else "Not reported.",
        "",
    ]
    return "\n".join(lines)


def _baseline_line(run: EvaluationRun, baseline: dict[str, Any] | None, *, checked: bool) -> str:
    if not checked:
        return "Baseline: check disabled."
    if baseline is None:
        return f"Baseline: none for {run.agent} / {run.tier}."
    return f"Baseline: {run.agent} / {run.tier}."


def _fixture_passes(value: Any) -> FixturePasses:
    return FixturePasses(passed=int(value.get("passed", 0)), trials=int(value.get("trials", 0)))


def _warning_lines(warnings: list[dict[str, Any]]) -> list[str]:
    if not warnings:
        return ["None."]
    return [f"- {warning['file']}: {warning['lines']} lines (limit {warning['limit']})" for warning in warnings]


def _json_value(value: Any) -> Any:
    if isinstance(value, (AggregateMetrics, Counts, Rates, FixturePasses)):
        return _json_value(asdict(value))
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _rate(value: float | None) -> str:
    return "—" if value is None else f"{value:.3f}"


def _rate_row(name: str, mean: float | None, minimum: float | None, deviation: float | None) -> str:
    return f"| {name} | {_rate(mean)} | {_rate(minimum)} | {_rate(deviation)} |"


def _difference(current: float | None, baseline: float | None) -> str:
    if current is None or baseline is None:
        return "no comparable baseline"
    change = current - baseline
    symbol = "▲" if change > 0 else "▼" if change < 0 else "—"
    return f"{symbol} {change:+.3f} vs baseline"


def _evidence_lines(entries: list[dict[str, Any]]) -> list[str]:
    if not entries:
        return ["None."]
    return [f"- {entry.get('id', 'unknown')}: {entry.get('evidence', 'no evidence')}" for entry in entries[:10]]


def _trial_lines(trials: list[dict[str, Any]]) -> list[str]:
    if not trials:
        return ["None."]
    return [f"- {trial.get('id', 'unknown trial')}: {trial.get('reason', 'no reason reported')}" for trial in trials]
