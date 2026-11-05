"""Run or replay isolated evaluation trials and persist each outcome immediately."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from time import monotonic
from typing import Any, Literal

import yaml

from eval.matcher import match
from eval.metrics import TrialMetrics, aggregate_trials, score_trial
from eval.report import EvaluationRun, FixturePasses, RegressionResult, write_results
from eval.validate import validate_findings

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = Path(__file__).with_name("config.yaml")
Agent = Literal["claude", "codex"]
Mode = Literal["code-only", "context"]
AgentCommand = Callable[[Path, Agent, str], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class Target:
    """One fixture or benchmark target and its canonical ground truth."""

    name: str
    root: Path
    expected_path: Path
    answers_path: Path | None = None


@dataclass(frozen=True)
class RunOptions:
    tier: Literal["fast", "full"]
    skill: str | None = None
    mode: Mode | None = None
    runs: int | None = None
    agent: Agent | None = None
    replay_dir: Path | None = None
    resume_dir: Path | None = None
    results_dir: Path | None = None
    baseline_check: bool = True
    allow_api_key: bool = False


def run(options: RunOptions, *, agent_command: AgentCommand | None = None, repo_root: Path = REPO_ROOT) -> tuple[Path, RegressionResult]:
    """Execute every missing trial for ``options`` and write the final report."""

    config = load_config(repo_root / "eval/config.yaml")
    agent = options.agent or config["default_agent"][options.tier]
    if options.replay_dir is None:
        guard_api_keys(options.allow_api_key)
    results_dir = options.resume_dir or options.results_dir or default_results_dir(repo_root)
    results_dir.mkdir(parents=True, exist_ok=True)
    trials_dir = results_dir / "trials"
    trials_dir.mkdir(exist_ok=True)
    targets = discover_targets(repo_root, options.tier, options.skill)
    modes: list[Mode] = [options.mode] if options.mode else ["code-only"]
    requested_runs = options.runs or int(config["trials_per_target"])
    max_trials = int(config["max_trials"][options.tier])
    specs = [(target, mode, number) for target in targets for mode in modes for number in range(1, requested_runs + 1)]
    completed = load_trial_records(trials_dir)
    attempted = sum(record["status"] != "skipped" for record in completed.values())
    stop_reason: str | None = None

    for target, mode, number in specs:
        key = trial_key(target, mode, number)
        existing = completed.get(key)
        if existing and existing["status"] != "skipped":
            continue
        if attempted >= max_trials:
            stop_reason = f"trial cap ({max_trials}) reached"
        if stop_reason:
            record = skipped_record(target, mode, number, stop_reason)
        else:
            record = execute_trial(
                target,
                mode,
                number,
                agent,
                options.replay_dir,
                agent_command,
                config,
            )
            attempted += 1
            if record["status"] == "usage-limit":
                stop_reason = record["reason"]
                record["status"] = "skipped"
        write_trial_record(trials_dir / f"{key}.json", record)
        completed[key] = record

    return results_dir, write_run_report(
        options.tier,
        agent,
        list(completed.values()),
        results_dir,
        baseline_check=options.baseline_check,
    )


def execute_trial(
    target: Target,
    mode: Mode,
    number: int,
    agent: Agent,
    replay_dir: Path | None,
    agent_command: AgentCommand | None,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Run one replay or live trial, returning a JSON-ready record."""

    started = monotonic()
    if replay_dir is not None:
        findings_path = replay_findings_path(replay_dir, target, mode, number)
        return score_findings(target, mode, number, findings_path, target.root, monotonic() - started)

    with tempfile.TemporaryDirectory(prefix="eval-trial-") as temporary_directory:
        copy_root = Path(temporary_directory) / "target"
        shutil.copytree(target.root, copy_root, ignore=shutil.ignore_patterns(".git"))
        install_trial_skills(copy_root)
        initialize_trial_git(copy_root)
        if mode == "context" and target.answers_path is not None:
            destination = copy_root / "docs/security/ANSWERS.input.md"
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(target.answers_path, destination)
        command = agent_command or default_agent_command(config)
        prompts = ["Run security-scan and write findings to docs/security/findings.json."]
        if mode == "context":
            prompts.insert(0, "Run security-context unattended, using docs/security/ANSWERS.input.md when present.")
        for prompt in prompts:
            completed = command(copy_root, agent, prompt)
            output = f"{completed.stdout}\n{completed.stderr}".lower()
            if is_usage_limit(output):
                return usage_limit_record(target, mode, number, output)
            if completed.returncode:
                return failed_record(target, mode, number, f"agent exited {completed.returncode}: {output[-500:]}")
        changed = changed_outside_security(copy_root)
        if changed:
            return failed_record(target, mode, number, f"modified outside docs/security/: {', '.join(changed)}")
        return score_findings(
            target,
            mode,
            number,
            copy_root / "docs/security/findings.json",
            copy_root,
            monotonic() - started,
        )


def score_findings(
    target: Target, mode: Mode, number: int, findings_path: Path, target_root: Path, duration: float
) -> dict[str, Any]:
    """Validate and match one findings file without ever raising on model output."""

    validation = validate_findings(findings_path)
    if validation.trial_status == "failed":
        return failed_record(target, mode, number, "; ".join(validation.errors), duration)
    truth = json.loads(target.expected_path.read_text())
    result = match(validation.findings, truth, str(target_root))
    metrics = score_trial(result, truth, target_id=target.name, mode=mode, run_id=number)
    return {
        "id": trial_key(target, mode, number),
        "target": target.name,
        "mode": mode,
        "run": number,
        "status": "ok",
        "duration_seconds": duration,
        "metrics": metrics_to_json(metrics),
        "false_negatives": result.false_negatives,
        "false_positives": [false_positive.finding for false_positive in result.false_positives],
    }


def write_run_report(tier: str, agent: str, records: list[dict[str, Any]], results_dir: Path, *, baseline_check: bool) -> RegressionResult:
    """Rehydrate successful trial metrics and delegate report/baseline rendering."""

    metrics = aggregate_trials(metric_from_json(record["metrics"]) for record in records if record["status"] == "ok")
    fixtures: dict[str, FixturePasses] = {}
    for record in records:
        if record["status"] != "ok":
            continue
        current = fixtures.get(record["target"], FixturePasses(0, 0))
        fixtures[record["target"]] = FixturePasses(
            current.passed + int(record["metrics"]["fixture_passed"]), current.trials + 1
        )
    run = EvaluationRun(
        tier=tier,
        agent=agent,
        metrics=metrics,
        fixture_passes=fixtures,
        failed_trials=[record for record in records if record["status"] == "failed"],
        skipped_trials=[record for record in records if record["status"] == "skipped"],
        false_negatives=[item for record in records for item in record.get("false_negatives", [])],
        false_positives=[item for record in records for item in record.get("false_positives", [])],
        tokens=None,
    )
    return write_results(run, results_dir, check_baseline=baseline_check)


def discover_targets(repo_root: Path, tier: str, skill: str | None) -> list[Target]:
    """Discover fixture targets; full tier will also include benchmark definitions when present."""

    fixtures = repo_root / "tests/fixtures"
    targets = [
        Target(path.name, path, path / "expected.json", (path / "answers.md") if (path / "answers.md").exists() else None)
        for path in sorted(fixtures.iterdir())
        if path.is_dir() and (path / "expected.json").exists() and (skill is None or path.name == skill)
    ]
    if tier == "full":
        # Benchmark support is intentionally deferred until benchmark definitions land;
        # fixtures still run in full tier as the spec requires.
        return targets
    return targets


def guard_api_keys(allow_api_key: bool) -> None:
    """Require subscription authentication unless the caller explicitly overrides it."""

    if not allow_api_key and any(os.environ.get(key) for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")):
        raise ValueError("API-key authentication is refused; pass --allow-api-key to override")


def default_agent_command(config: dict[str, Any]) -> AgentCommand:
    """Build the verified noninteractive Claude/Codex commands for live trials."""

    def invoke(target_root: Path, agent: Agent, prompt: str) -> subprocess.CompletedProcess[str]:
        if agent == "claude":
            command = [
                "claude", "-p", prompt, "--plugin-dir", str(REPO_ROOT), "--output-format", "json",
                "--model", config["models"]["claude"], "--allowedTools", "Read,Grep,Glob,Write,Edit,Bash(git diff:*),Bash(git log:*)",
            ]
        else:
            command = [
                "codex", "--model", config["models"]["codex"], "exec", "--cd", str(target_root),
                "--sandbox", "workspace-write", prompt,
            ]
        return subprocess.run(command, cwd=target_root, capture_output=True, text=True, check=False)

    return invoke


def replay_findings_path(replay_dir: Path, target: Target, mode: Mode, number: int) -> Path:
    """Find a target-specific recording first, then a single reusable replay file."""

    candidates = [
        replay_dir / target.name / mode / str(number) / "findings.json",
        replay_dir / target.name / f"{mode}-{number}.json",
        replay_dir / "findings.json",
    ]
    candidates.extend(sorted(replay_dir.rglob("findings.json")))
    candidates.extend(sorted(replay_dir.glob("*finding*.json")))
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"no replay findings for {target.name}/{mode}/{number} under {replay_dir}")


def initialize_trial_git(target_root: Path) -> None:
    """Give each agent an isolated baseline that can be diffed after it exits."""

    for command in (["git", "init", "--quiet"], ["git", "add", "-A"], ["git", "-c", "user.name=eval", "-c", "user.email=eval@example.invalid", "commit", "--quiet", "-m", "trial baseline"]):
        subprocess.run(command, cwd=target_root, check=True, capture_output=True, text=True)


def install_trial_skills(target_root: Path) -> None:
    """Make the repository's portable skills available to a Codex trial."""

    destination = target_root / ".agents/skills"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(REPO_ROOT / "skills", destination)


def changed_outside_security(target_root: Path) -> list[str]:
    """Return every changed path outside the sole allowed output directory."""

    changed = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=target_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    paths = [line[3:] for line in changed if len(line) > 3]
    return [path for path in paths if not path.startswith("docs/security/")]


def is_usage_limit(output: str) -> bool:
    return any(marker in output for marker in ("usage limit", "rate limit", "quota exceeded"))


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    return yaml.safe_load(path.read_text()) or {}


def default_results_dir(repo_root: Path) -> Path:
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=repo_root, check=True, capture_output=True, text=True).stdout.strip()
    return repo_root / "eval/results" / f"{date.today().isoformat()}-{commit}"


def trial_key(target: Target, mode: Mode, number: int) -> str:
    return f"{target.name}-{mode}-{number}"


def load_trial_records(trials_dir: Path) -> dict[str, dict[str, Any]]:
    return {path.stem: json.loads(path.read_text()) for path in trials_dir.glob("*.json")}


def write_trial_record(path: Path, record: dict[str, Any]) -> None:
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")


def failed_record(target: Target, mode: Mode, number: int, reason: str, duration: float = 0) -> dict[str, Any]:
    return {"id": trial_key(target, mode, number), "target": target.name, "mode": mode, "run": number, "status": "failed", "reason": reason, "duration_seconds": duration}


def usage_limit_record(target: Target, mode: Mode, number: int, reason: str) -> dict[str, Any]:
    return {"id": trial_key(target, mode, number), "target": target.name, "mode": mode, "run": number, "status": "usage-limit", "reason": reason[-500:]}


def skipped_record(target: Target, mode: Mode, number: int, reason: str) -> dict[str, Any]:
    return {"id": trial_key(target, mode, number), "target": target.name, "mode": mode, "run": number, "status": "skipped", "reason": reason}


def metrics_to_json(metrics: TrialMetrics) -> dict[str, Any]:
    return {
        "counts": metrics.counts.__dict__, "rates": metrics.rates.__dict__, "fixture_passed": metrics.fixture_passed,
        "matched_truth": list(metrics.matched_truth), "truth_entries": list(metrics.truth_entries), "breakdowns": {dimension: {value: counts.__dict__ for value, counts in values.items()} for dimension, values in metrics.breakdowns.items()}, "run_id": metrics.run_id,
    }


def metric_from_json(document: dict[str, Any]) -> TrialMetrics:
    from eval.metrics import Counts, Rates

    return TrialMetrics(
        counts=Counts(**document["counts"]), rates=Rates(**document["rates"]), fixture_passed=document["fixture_passed"],
        matched_truth=frozenset(tuple(value) if isinstance(value, list) else value for value in document["matched_truth"]),
        truth_entries=frozenset(tuple(value) if isinstance(value, list) else value for value in document["truth_entries"]),
        breakdowns={dimension: {value: Counts(**counts) for value, counts in values.items()} for dimension, values in document["breakdowns"].items()}, run_id=document["run_id"],
    )
