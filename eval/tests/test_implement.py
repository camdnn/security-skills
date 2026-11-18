"""Implement-skill eval (TICKET-001 §7.7): each criterion is measured, not taken from the agent's claims.

The fixture here is a tiny Python app so the tests need no Node.js; the eval itself is
language-agnostic through ``test_command``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from eval.implement import ImplementOptions, load_implement_target, run_implement
from eval.runner import REPO_ROOT, discover_targets

DATA = Path(__file__).parent / "data"
RUN_FILES = "import runpy, sys\nfor path in sys.argv[1:]:\n    runpy.run_path(path, run_name='__main__')\n"
VULNERABLE = "def calculate(expression):\n    return eval(expression)\n"
FIXED = "import ast\n\n\ndef calculate(expression):\n    return ast.literal_eval(expression)\n"
ORIGINAL_TEST = "from src.calc import calculate\n\nassert calculate('2') == 2\n"
RED_TEST = (
    "from src.calc import calculate\n\ntry:\n    calculate(\"__import__('os').getcwd()\")\nexcept ValueError:\n    pass\n"
    "else:\n    raise AssertionError('code was executed')\n"
)


def finding(identifier: str, **overrides: object) -> dict:
    document = json.loads((DATA / "finding-example.json").read_text())
    return document | {
        "id": identifier, "skill": "injection-check", "cwe": "CWE-94", "file": "src/calc.py", "line": 2, "end_line": 2,
        "context_ref": None, "mode": "code-only",
    } | overrides


def implement_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    fixture = repo / "tests/fixtures/app"
    (fixture / "src").mkdir(parents=True)
    (fixture / "test").mkdir()
    (fixture / "src/__init__.py").write_text("")
    (fixture / "src/calc.py").write_text(VULNERABLE)
    (fixture / "test/test_calc.py").write_text(ORIGINAL_TEST)
    (fixture / "requirements.txt").write_text("pyyaml==3.12\n")
    findings = [
        finding("SEC-0001"),
        finding("SEC-0002", skill="dependency-check", cwe="CWE-1104", file="requirements.txt", line=1, end_line=1),
    ]
    (fixture / "findings.json").write_text(json.dumps(findings))
    (fixture / "implement.yaml").write_text(
        "findings: findings.json\n"
        f"test_command: [{json.dumps(sys.executable)}, -c, {json.dumps(RUN_FILES)}]\n"
        "test_glob: 'test/**.py'\n"
        "expect_needs_human: [SEC-0002]\n"
    )
    (repo / "eval").mkdir()
    (repo / "eval/config.yaml").write_text(
        "trials_per_target: 1\nline_tolerance: 5\ndefault_agent:\n  fast: claude\n  full: codex\nmodels:\n  claude: t\n  codex: t\n"
    )
    shutil.copyfile(REPO_ROOT / "eval/cwe_families.json", repo / "eval/cwe_families.json")
    return repo


def agent(
    *,
    fix: bool = True,
    test: str | None = RED_TEST,
    claims: list[dict] | None = None,
    edit_original_test: str | None = None,
    branch: bool = True,
) -> Callable[[Path, str, str], subprocess.CompletedProcess[str]]:
    def implement(root: Path, name: str, prompt: str) -> subprocess.CompletedProcess[str]:
        assert (root / "docs/security/IMPLEMENT.input.md").exists()
        assert not (root / "implement.yaml").exists() and not (root / "findings.json").exists()
        if branch:
            subprocess.run(["git", "checkout", "-q", "-b", "security/fixes"], cwd=root, check=True)
        if test is not None:
            (root / "test/test_calc_safe.py").write_text(test)
        if fix:
            (root / "src/calc.py").write_text(FIXED)
        if edit_original_test is not None:
            (root / "test/test_calc.py").write_text(edit_original_test)
        default_claims = [
            {"id": "SEC-0001", "status": "fixed", "tests": ["test/test_calc_safe.py"]},
            {"id": "SEC-0002", "status": "needs-human", "tests": []},
        ]
        (root / "docs/security/implement-results.json").write_text(json.dumps(claims if claims is not None else default_claims))
        (root / "docs/security/IMPLEMENT-LOG.md").write_text("# Implement log\n")
        return subprocess.CompletedProcess([name], 0, "", "")

    return implement


def scanner(findings: list[dict] | None = None) -> Callable[[Path, str, str], subprocess.CompletedProcess[str]]:
    def scan(root: Path, name: str, prompt: str) -> subprocess.CompletedProcess[str]:
        assert not (root / "docs/security/implement-results.json").exists()
        (root / "docs/security").mkdir(parents=True, exist_ok=True)
        (root / "docs/security/findings.json").write_text(json.dumps(findings or []))
        return subprocess.CompletedProcess([name], 0, "", "")

    return scan


def run(tmp_path: Path, implement, scan=None) -> tuple[dict, dict]:
    repo = implement_repo(tmp_path)
    results, exit_code = run_implement(
        ImplementOptions(results_dir=tmp_path / "results"), agent_command=implement, scan_command=scan or scanner(), repo_root=repo
    )
    assert exit_code == 0
    metrics = json.loads((results / "metrics.json").read_text())
    trial = json.loads(next((results / "trials").glob("*.json")).read_text())
    return metrics, trial


def test_a_proper_tdd_fix_is_verified(tmp_path: Path):
    metrics, trial = run(tmp_path, agent())

    assert metrics["verified_fix_rate"]["mean"] == 1
    assert metrics["needs_human_correct"] == metrics["needs_human_expected"] == 1
    assert trial["findings"]["SEC-0001"]["verified"] is True
    assert trial["warnings"] == []


def test_claimed_fix_without_a_new_test_is_not_verified(tmp_path: Path):
    _, trial = run(tmp_path, agent(test=None))

    criteria = trial["findings"]["SEC-0001"]["criteria"]
    assert criteria["red_before_fix"] is False and criteria["green_after_fix"] is False
    assert trial["verified_fix_rate"] == 0


def test_a_test_that_already_passes_before_the_fix_is_not_red(tmp_path: Path):
    _, trial = run(tmp_path, agent(test="assert True\n"))

    assert trial["findings"]["SEC-0001"]["criteria"]["red_before_fix"] is False


def test_test_without_fix_fails_green(tmp_path: Path):
    _, trial = run(tmp_path, agent(fix=False))

    criteria = trial["findings"]["SEC-0001"]["criteria"]
    assert criteria["red_before_fix"] is True and criteria["green_after_fix"] is False


def test_weakening_an_original_test_does_not_pass_the_full_suite(tmp_path: Path):
    # The original test needs behaviour the fix removes; the agent rewrites it instead of noticing.
    repo_test = "from src.calc import calculate\n\nassert calculate('2 + 2') == 4\n"
    implement = agent(edit_original_test="assert True\n")

    repo = implement_repo(tmp_path)
    (repo / "tests/fixtures/app/test/test_calc.py").write_text(repo_test)
    results, _ = run_implement(
        ImplementOptions(results_dir=tmp_path / "results"), agent_command=implement, scan_command=scanner(), repo_root=repo
    )
    trial = json.loads(next((results / "trials").glob("*.json")).read_text())

    assert trial["findings"]["SEC-0001"]["criteria"]["full_suite_passes"] is False


def test_finding_still_reported_by_the_rescan_is_not_gone(tmp_path: Path):
    _, trial = run(tmp_path, agent(), scanner([finding("SEC-0001", line=5, end_line=5)]))

    assert trial["findings"]["SEC-0001"]["criteria"]["finding_gone"] is False


def test_new_finding_in_a_changed_file_fails_no_new_findings(tmp_path: Path):
    new = finding("SEC-0009", skill="secrets-check", cwe="CWE-798", file="src/calc.py", line=1, end_line=1)
    _, trial = run(tmp_path, agent(), scanner([new]))

    assert trial["findings"]["SEC-0001"]["criteria"]["no_new_findings"] is False
    assert [item["id"] for item in trial["new_findings"]] == ["SEC-0009"]


def test_untestable_finding_claimed_fixed_is_flagged(tmp_path: Path):
    claims = [
        {"id": "SEC-0001", "status": "fixed", "tests": ["test/test_calc_safe.py"]},
        {"id": "SEC-0002", "status": "fixed", "tests": []},
    ]
    metrics, _ = run(tmp_path, agent(claims=claims))

    assert metrics["needs_human_correct"] == 0
    assert "expected needs-human, claimed fixed" in (tmp_path / "results/report.md").read_text()


def test_working_on_the_default_branch_is_a_warning(tmp_path: Path):
    _, trial = run(tmp_path, agent(branch=False))

    assert "fixes were not made on a separate branch" in trial["warnings"]


def test_missing_results_file_fails_the_trial(tmp_path: Path):
    def silent(root: Path, name: str, prompt: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([name], 0, "", "")

    repo = implement_repo(tmp_path)
    results, _ = run_implement(ImplementOptions(results_dir=tmp_path / "results"), agent_command=silent, scan_command=scanner(), repo_root=repo)

    assert json.loads((results / "metrics.json").read_text())["failed_trials"][0]["reason"].startswith("cannot read")


def test_usage_limit_makes_the_eval_run_incomplete(tmp_path: Path):
    def limited(root: Path, name: str, prompt: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess([name], 1, "", "Usage limit reached")

    repo = implement_repo(tmp_path)
    _, exit_code = run_implement(ImplementOptions(results_dir=tmp_path / "results"), agent_command=limited, scan_command=scanner(), repo_root=repo)

    assert exit_code == 2


def test_repository_implement_fixture_is_valid_and_not_a_detection_target():
    target = load_implement_target(REPO_ROOT / "tests/fixtures/implement")

    assert target.expect_needs_human == {"SEC-0005"}
    assert "implement" not in [t.name for t in discover_targets(REPO_ROOT, "full", None)]
    for item in target.findings:
        lines = (target.root / item["file"]).read_text().splitlines()
        assert item["line"] <= len(lines), item["id"]


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_repository_implement_fixture_suite_passes_before_any_fix():
    target = load_implement_target(REPO_ROOT / "tests/fixtures/implement")
    version = subprocess.run(["node", "--version"], check=False, capture_output=True, text=True).stdout.strip().lstrip("v").split(".")
    if (int(version[0]), int(version[1])) < (22, 6):
        pytest.skip("type stripping needs Node.js 22.6 or later")
    tests = sorted(str(p.relative_to(target.root)) for p in target.root.glob("test/*.test.ts"))

    completed = subprocess.run(target.test_command + tests, check=False, cwd=target.root, capture_output=True, text=True)

    assert completed.returncode == 0, completed.stdout + completed.stderr
