"""Implement-skill eval (TICKET-001 §7.7): verify TDD fixes instead of trusting the agent's claims.

For every finding in an implement target, a trial passes the finding only when:

1. a new or changed test fails on the pre-fix code (RED, proven by running it there);
2. that test passes after the fix (GREEN);
3. the full suite passes after the fix, with the original tests at their pre-fix versions;
4. a fresh scan of the fixed code no longer reports the finding;
5. that scan reports no new finding in a file the trial changed.

6. Findings the target marks untestable must be logged ``needs-human``, never ``fixed``.

Verified fix rate = findings passing 1-5 / findings attempted (every finding not expected
to need a human). The agent's ``docs/security/implement-results.json`` says which tests
belong to which finding; everything else is measured.
"""

from __future__ import annotations

import fnmatch
import json
import shutil
import statistics
import subprocess
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from time import monotonic
from typing import Any

import yaml

from eval.runner import (
    REPO_ROOT,
    TRIAL_PROMPTS,
    Agent,
    AgentCommand,
    Target,
    copy_target,
    default_agent_command,
    guard_api_keys,
    initialize_trial_git,
    install_trial_skills,
    is_usage_limit,
    load_config,
    load_cwe_families,
)
from eval.validate import validate_findings

IMPLEMENT_PROMPTS: dict[Agent, str] = {
    "claude": "/analyzer:implement",
    "codex": (
        "Run implement unattended. docs/security/IMPLEMENT.input.md is present and selects the findings in "
        "docs/security/findings.json to fix."
    ),
}
UNATTENDED_SELECTION = "# Unattended implement selection (written by the checker)\n\nselect: all\n"
RESULTS_FILE = "docs/security/implement-results.json"
TestRunner = Callable[[Path, list[str]], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class ImplementTarget:
    """A fixture app with a test suite and the recorded findings `implement` must fix."""

    name: str
    root: Path
    findings: list[dict[str, Any]]
    test_command: list[str]
    test_glob: str
    expect_needs_human: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class ImplementOptions:
    agent: Agent | None = None
    runs: int | None = None
    results_dir: Path | None = None
    allow_api_key: bool = False


def load_implement_target(directory: Path) -> ImplementTarget:
    """Read ``implement.yaml`` and its findings file."""

    definition = yaml.safe_load((directory / "implement.yaml").read_text()) or {}
    for key in ("findings", "test_command", "test_glob"):
        if key not in definition:
            raise ValueError(f"{directory / 'implement.yaml'}: missing {key!r}")
    validation = validate_findings(directory / definition["findings"])
    if validation.trial_status != "ok":
        raise ValueError(f"{directory}: findings are not schema-valid: {'; '.join(validation.errors)}")
    findings = list(validation.findings)
    expected = frozenset(str(item) for item in definition.get("expect_needs_human") or ())
    unknown = expected - {finding["id"] for finding in findings}
    if unknown:
        raise ValueError(f"{directory}: expect_needs_human names unknown findings: {', '.join(sorted(unknown))}")
    return ImplementTarget(
        name=directory.name,
        root=directory,
        findings=findings,
        test_command=[str(part) for part in definition["test_command"]],
        test_glob=str(definition["test_glob"]),
        expect_needs_human=expected,
    )


def discover_implement_targets(repo_root: Path) -> list[ImplementTarget]:
    fixtures = repo_root / "tests/fixtures"
    return [load_implement_target(path.parent) for path in sorted(fixtures.glob("*/implement.yaml"))]


def run_implement(
    options: ImplementOptions,
    *,
    agent_command: AgentCommand | None = None,
    scan_command: AgentCommand | None = None,
    test_runner: TestRunner | None = None,
    repo_root: Path = REPO_ROOT,
    clock: Callable[[], datetime] = datetime.now,
) -> tuple[Path, int]:
    """Run every implement trial and write ``metrics.json`` + ``report.md``; return (folder, exit code)."""

    config = load_config(repo_root / "eval/config.yaml")
    agent: Agent = options.agent or config["default_agent"]["fast"]
    guard_api_keys(options.allow_api_key)
    targets = discover_implement_targets(repo_root)
    if not targets:
        raise ValueError("no implement targets: add tests/fixtures/<name>/implement.yaml")
    results_dir = options.results_dir or default_implement_dir(repo_root, clock())
    trials_dir = results_dir / "trials"
    if any(trials_dir.glob("*.json")):
        raise ValueError(f"{results_dir} already holds implement trials; choose another folder with --results-dir")
    trials_dir.mkdir(parents=True, exist_ok=True)
    runs = options.runs or int(config["trials_per_target"])
    implement = agent_command or implement_agent_command(config)
    scan = scan_command or default_agent_command(config)
    tests = test_runner or run_tests
    families = load_cwe_families(repo_root / "eval/cwe_families.json")["cwe_to_family"]
    tolerance = int(config.get("line_tolerance", 5))

    records: list[dict[str, Any]] = []
    stop_reason: str | None = None
    for target in targets:
        for number in range(1, runs + 1):
            key = f"{target.name}-implement-{number}"
            if stop_reason:
                record: dict[str, Any] = {"id": key, "target": target.name, "run": number, "status": "skipped", "reason": stop_reason}
            else:
                record = implement_trial(target, number, agent, implement, scan, tests, families, tolerance) | {"id": key}
                if record["status"] == "usage-limit":
                    stop_reason = record["reason"]
                    record["status"] = "skipped"
            (trials_dir / f"{key}.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
            records.append(record)

    metrics = aggregate(agent, records)
    (results_dir / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n")
    (results_dir / "report.md").write_text(render_report(metrics, records))
    return results_dir, 2 if metrics["skipped_trials"] else 0


def implement_trial(
    target: ImplementTarget,
    number: int,
    agent: Agent,
    implement: AgentCommand,
    scan: AgentCommand,
    tests: TestRunner,
    families: dict[str, str],
    tolerance: int,
) -> dict[str, Any]:
    started = monotonic()
    base = {"target": target.name, "run": number}
    with tempfile.TemporaryDirectory(prefix="eval-implement-") as temporary_directory:
        work = Path(temporary_directory)
        root = work / "target"
        copy_target(Target(target.name, target.root, target.root / "implement.yaml"), root)
        (root / "findings.json").unlink(missing_ok=True)
        security = root / "docs/security"
        security.mkdir(parents=True, exist_ok=True)
        (security / "findings.json").write_text(json.dumps(target.findings, indent=2) + "\n")
        (security / "IMPLEMENT.input.md").write_text(UNATTENDED_SELECTION)
        install_trial_skills(root)
        initialize_trial_git(root)
        baseline = git(root, "rev-parse", "HEAD")
        baseline_branch = git(root, "branch", "--show-current")

        completed = implement(root, agent, IMPLEMENT_PROMPTS[agent])
        output = f"{completed.stdout}\n{completed.stderr}".lower()
        if is_usage_limit(completed, output):
            return base | {"status": "usage-limit", "reason": output[-500:]}
        if completed.returncode:
            return base | {"status": "failed", "reason": f"agent exited {completed.returncode}: {output[-500:]}"}

        claims, claim_error = read_claims(root / RESULTS_FILE)
        if claim_error:
            return base | {"status": "failed", "reason": claim_error, "duration_seconds": monotonic() - started}

        commit_any_changes(root)
        changed = changed_files(root, baseline)
        test_files_now = sorted(path for path in tracked_files(root) if fnmatch.fnmatch(path, target.test_glob))
        new_tests = {path for path in changed if fnmatch.fnmatch(path, target.test_glob) and (root / path).is_file()}

        pristine = work / "pre-fix"
        export_commit(root, baseline, pristine)
        original_tests = sorted(
            path.relative_to(pristine).as_posix()
            for path in pristine.rglob("*")
            if path.is_file() and fnmatch.fnmatch(path.relative_to(pristine).as_posix(), target.test_glob)
        )
        # RED: the trial's new or changed tests, run against the pre-fix code.
        red_root = work / "red"
        shutil.copytree(pristine, red_root)
        overlay(root, red_root, sorted(new_tests))
        # Full suite: the original tests at their pre-fix versions plus the new tests, on the fixed code,
        # so weakening an existing test can't make the suite pass.
        suite_root = work / "suite"
        shutil.copytree(root, suite_root, ignore=shutil.ignore_patterns(".git"))
        overlay(pristine, suite_root, original_tests)
        suite_tests = sorted(set(test_files_now) | set(original_tests))
        full_suite = tests(suite_root, target.test_command + suite_tests).returncode == 0
        rescan, rescan_error = fresh_scan(root, work / "rescan", agent, scan)
        new_findings = [
            finding for finding in rescan
            if not any(same_vulnerability(finding, original, families, tolerance) for original in target.findings)
            and finding.get("file") in changed
        ]

        results = {}
        for finding in target.findings:
            claim = claims.get(finding["id"], {})
            status = claim.get("status", "missing")
            if finding["id"] in target.expect_needs_human:
                results[finding["id"]] = {"expected": "needs-human", "claimed": status, "needs_human_logged": status == "needs-human"}
                continue
            own_tests = sorted(set(claim.get("tests", [])) & new_tests)
            red = bool(own_tests) and tests(red_root, target.test_command + own_tests).returncode != 0
            green = bool(own_tests) and tests(root, target.test_command + own_tests).returncode == 0
            gone = rescan_error is None and not any(same_vulnerability(item, finding, families, tolerance) for item in rescan)
            criteria = {
                "claimed_fixed": status == "fixed",
                "red_before_fix": red,
                "green_after_fix": green,
                "full_suite_passes": full_suite,
                "finding_gone": gone,
                "no_new_findings": rescan_error is None and not new_findings,
            }
            results[finding["id"]] = {"expected": "fixed", "claimed": status, "tests": own_tests, "criteria": criteria, "verified": all(criteria.values())}

        attempted = [result for result in results.values() if result["expected"] == "fixed"]
        verified = sum(result["verified"] for result in attempted)
        warnings = []
        if git(root, "branch", "--show-current") == baseline_branch:
            warnings.append("fixes were not made on a separate branch")
        if not (security / "IMPLEMENT-LOG.md").exists():
            warnings.append("docs/security/IMPLEMENT-LOG.md was not written")
        if rescan_error:
            warnings.append(f"re-scan unusable: {rescan_error}")
        return base | {
            "status": "ok",
            "duration_seconds": monotonic() - started,
            "findings": results,
            "attempted": len(attempted),
            "verified": verified,
            "verified_fix_rate": verified / len(attempted) if attempted else None,
            "needs_human_correct": sum(r.get("needs_human_logged", False) for r in results.values()),
            "needs_human_expected": len(target.expect_needs_human),
            "new_findings": new_findings,
            "warnings": warnings,
        }


def read_claims(path: Path) -> tuple[dict[str, dict[str, Any]], str | None]:
    """Parse the agent's per-finding claims; treat the file as untrusted data."""

    try:
        document = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return {}, f"cannot read {RESULTS_FILE}: {error}"
    if not isinstance(document, list):
        return {}, f"{RESULTS_FILE} must be a JSON array"
    claims: dict[str, dict[str, Any]] = {}
    for item in document:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            return {}, f"{RESULTS_FILE}: every entry needs a string id"
        if item.get("status") not in ("fixed", "needs-human", "skipped"):
            return {}, f"{RESULTS_FILE}: {item['id']} has status {item.get('status')!r}"
        tests = item.get("tests", [])
        if not isinstance(tests, list) or not all(isinstance(test, str) for test in tests):
            return {}, f"{RESULTS_FILE}: {item['id']} tests must be a list of paths"
        claims[item["id"]] = item
    return claims, None


def same_vulnerability(finding: dict[str, Any], original: dict[str, Any], families: dict[str, str], tolerance: int) -> bool:
    """The checker's notion of one vulnerability: same file and CWE family, lines within the tolerance."""

    if finding.get("file") != original["file"]:
        return False
    family = families.get(str(finding.get("cwe")))
    if family is None or family != families.get(original["cwe"]):
        return False
    try:
        line, end = int(finding["line"]), int(finding["end_line"])
    except (KeyError, TypeError, ValueError):
        return False
    return line <= original["end_line"] + tolerance and end >= original["line"] - tolerance


def fresh_scan(root: Path, scan_root: Path, agent: Agent, scan: AgentCommand) -> tuple[list[dict[str, Any]], str | None]:
    """Scan a clean copy of the fixed code, without the trial's docs/security/ output."""

    shutil.copytree(root, scan_root, ignore=shutil.ignore_patterns(".git"))
    shutil.rmtree(scan_root / "docs/security", ignore_errors=True)
    initialize_trial_git(scan_root)
    completed = scan(scan_root, agent, TRIAL_PROMPTS[agent][1])
    if completed.returncode:
        return [], f"scan exited {completed.returncode}"
    validation = validate_findings(scan_root / "docs/security/findings.json")
    if validation.trial_status != "ok":
        return [], "; ".join(validation.errors)
    return list(validation.findings), None


def run_tests(root: Path, command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return subprocess.CompletedProcess(command, 1, "", str(error))


def implement_agent_command(config: dict[str, Any]) -> AgentCommand:
    """Like the scan command, but `implement` must edit code, run git and run the test suite."""

    def invoke(target_root: Path, agent: Agent, prompt: str) -> subprocess.CompletedProcess[str]:
        if agent == "claude":
            command = [
                "claude", "-p", prompt, "--plugin-dir", str(REPO_ROOT), "--output-format", "json",
                "--model", config["models"]["claude"],
                "--strict-mcp-config", "--setting-sources", "project",
                "--allowedTools", "Read,Grep,Glob,Write,Edit,Bash(git:*),Bash(node:*),Bash(npm test:*),Bash(npm run test:*)",
                "--disallowedTools", "WebFetch,WebSearch",
            ]
        else:
            command = [
                "codex", "--model", config["models"]["codex"], "exec", "--cd", str(target_root),
                "--sandbox", "workspace-write", prompt,
            ]
        return subprocess.run(command, cwd=target_root, capture_output=True, text=True, check=False)

    return invoke


def overlay(source: Path, destination: Path, paths: list[str]) -> None:
    for path in paths:
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / path, target)


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(["git", *arguments], cwd=root, check=True, capture_output=True, text=True).stdout.strip()


def commit_any_changes(root: Path) -> None:
    """Snapshot uncommitted work so the diff against the baseline sees everything."""

    git(root, "add", "-A")
    if git(root, "status", "--porcelain"):
        git(root, "-c", "user.name=eval", "-c", "user.email=eval@example.invalid", "commit", "--quiet", "-m", "trial snapshot")


def changed_files(root: Path, baseline: str) -> set[str]:
    return {line for line in git(root, "diff", "--name-only", baseline, "HEAD").splitlines() if line}


def tracked_files(root: Path) -> list[str]:
    return [line for line in git(root, "ls-files").splitlines() if line]


def export_commit(root: Path, commit: str, destination: Path) -> None:
    """Write the tree of ``commit`` (the pre-fix code) into ``destination``."""

    destination.mkdir(parents=True)
    archive = destination.parent / "baseline.tar"
    with archive.open("wb") as handle:
        subprocess.run(["git", "archive", commit], cwd=root, check=True, stdout=handle)
    with tarfile.open(archive) as tar:
        tar.extractall(destination, filter="data")
    archive.unlink()


def aggregate(agent: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    ok = [record for record in records if record["status"] == "ok"]
    rates = [record["verified_fix_rate"] for record in ok if record["verified_fix_rate"] is not None]
    per_finding: dict[str, dict[str, int]] = {}
    for record in ok:
        for finding_id, result in record["findings"].items():
            counts = per_finding.setdefault(finding_id, {"passed": 0, "trials": 0})
            counts["trials"] += 1
            counts["passed"] += int(result.get("verified", result.get("needs_human_logged", False)))
    return {
        "tier": "implement",
        "agent": agent,
        "verified_fix_rate": {
            "mean": statistics.fmean(rates) if rates else None,
            "minimum": min(rates) if rates else None,
            "std_dev": statistics.pstdev(rates) if len(rates) > 1 else (0.0 if rates else None),
        },
        "needs_human_correct": sum(record["needs_human_correct"] for record in ok),
        "needs_human_expected": sum(record["needs_human_expected"] for record in ok),
        "per_finding": per_finding,
        "failed_trials": [record for record in records if record["status"] == "failed"],
        "skipped_trials": [record for record in records if record["status"] == "skipped"],
        "warnings": sorted({f"{record['id']}: {warning}" for record in ok for warning in record["warnings"]}),
    }


def render_report(metrics: dict[str, Any], records: list[dict[str, Any]]) -> str:
    rate = metrics["verified_fix_rate"]

    def show(value: float | None) -> str:
        return "—" if value is None else f"{value:.3f}"

    lines = [
        "# Implement eval report",
        "",
        "## Summary",
        "",
        "| Metric | Mean | Minimum | Std-dev |",
        "| --- | ---: | ---: | ---: |",
        f"| Verified fix rate | {show(rate['mean'])} | {show(rate['minimum'])} | {show(rate['std_dev'])} |",
        "",
        f"Untestable findings logged as needs-human: {metrics['needs_human_correct']}/{metrics['needs_human_expected']}.",
        "",
        "## Agent",
        "",
        metrics["agent"],
        "",
        "## Per finding",
        "",
        "| Finding | Passed | Trials |",
        "| --- | ---: | ---: |",
        *[f"| {finding} | {counts['passed']} | {counts['trials']} |" for finding, counts in sorted(metrics["per_finding"].items())],
        "",
        "## Failed criteria",
        "",
    ]
    failures = [
        f"- {record['id']} {finding}: {', '.join(name for name, passed in result['criteria'].items() if not passed)}"
        for record in records if record["status"] == "ok"
        for finding, result in sorted(record["findings"].items())
        if result.get("criteria") and not result["verified"]
    ]
    wrong_human = [
        f"- {record['id']} {finding}: expected needs-human, claimed {result['claimed']}"
        for record in records if record["status"] == "ok"
        for finding, result in sorted(record["findings"].items())
        if result["expected"] == "needs-human" and not result["needs_human_logged"]
    ]
    lines += (failures + wrong_human) or ["None."]
    lines += ["", "## Warnings", "", *([f"- {warning}" for warning in metrics["warnings"]] or ["None."])]
    lines += ["", "## Failed trials", "", *([f"- {t['id']}: {t['reason']}" for t in metrics["failed_trials"]] or ["None."])]
    lines += ["", "## Skipped trials", "", *([f"- {t['id']}: {t['reason']}" for t in metrics["skipped_trials"]] or ["None."]), ""]
    return "\n".join(lines)


def default_implement_dir(repo_root: Path, now: datetime) -> Path:
    commit = git(repo_root, "rev-parse", "--short", "HEAD")
    return repo_root / "eval/results" / f"{now.date().isoformat()}-{commit}-implement"
