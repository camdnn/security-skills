"""Replay, sandbox enforcement, and resume behavior for evaluation trials."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from eval.runner import (
    RunOptions,
    Target,
    default_agent_command,
    execute_trial,
    guard_api_keys,
    install_trial_skills,
    run,
)

DATA = Path(__file__).parent / "data"


def finding() -> dict:
    document = json.loads((DATA / "finding-example.json").read_text())
    return document | {
        "skill": "injection-check",
        "cwe": "CWE-89",
        "file": "vulnerable/query.ts",
        "line": 2,
        "end_line": 2,
    }


def expected() -> dict:
    return {
        "truth": [
            {
                "id": "SQLI-01",
                "cwe": "CWE-89",
                "locations": [{"file": "vulnerable/query.ts", "start_line": 2, "end_line": 2}],
                "evidence": "database.query(input)",
                "requires_context": False,
                "description": "Injected SQL",
                "source": "runner test",
            }
        ]
    }


def runner_repo(tmp_path: Path, *, max_trials: int = 30) -> tuple[Path, Target]:
    fixture = tmp_path / "tests/fixtures/injection-check"
    vulnerable = fixture / "vulnerable"
    vulnerable.mkdir(parents=True)
    (vulnerable / "query.ts").write_text("const input = request.query.q;\ndatabase.query(input);\n")
    expected_path = fixture / "expected.json"
    expected_path.write_text(json.dumps(expected()))
    config = tmp_path / "eval/config.yaml"
    config.parent.mkdir()
    config.write_text(
        "trials_per_target: 2\nmax_trials:\n  fast: "
        f"{max_trials}\n  full: 30\ndefault_agent:\n  fast: claude\n  full: codex\nmodels:\n  claude: test\n  codex: test\n"
    )
    return tmp_path, Target("injection-check", fixture, expected_path)


def successful_agent(target: Path, agent: str, prompt: str) -> subprocess.CompletedProcess[str]:
    output = target / "docs/security/findings.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps([finding()]))
    return subprocess.CompletedProcess([agent], 0, "", "")


def test_replay_runs_end_to_end_and_writes_each_trial(tmp_path: Path):
    repo, _ = runner_repo(tmp_path)
    replay = tmp_path / "replay"
    replay.mkdir()
    (replay / "findings.json").write_text(json.dumps([finding()]))

    results, outcome = run(
        RunOptions(tier="fast", replay_dir=replay, results_dir=tmp_path / "results", baseline_check=False),
        repo_root=repo,
    )

    assert outcome.exit_code == 0
    assert len(list((results / "trials").glob("*.json"))) == 2
    assert json.loads((results / "metrics.json").read_text())["metrics"]["mean"]["f1"] == 1


def test_run_cli_accepts_replay_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    from eval.__main__ import main

    replay = tmp_path / "replay"
    replay.mkdir()
    (replay / "findings.json").write_text(json.dumps([finding()]))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m eval",
            "run",
            "--tier",
            "fast",
            "--runs",
            "1",
            "--replay",
            str(replay),
            "--resume",
            str(tmp_path / "results"),
            "--no-baseline-check",
        ],
    )

    assert main() == 0
    assert (tmp_path / "results" / "metrics.json").exists()


def test_live_trial_fails_when_agent_modifies_outside_security(tmp_path: Path):
    _, target = runner_repo(tmp_path)

    def mutating_agent(root: Path, agent: str, prompt: str) -> subprocess.CompletedProcess[str]:
        (root / "vulnerable/query.ts").write_text("changed\n")
        return subprocess.CompletedProcess([agent], 0, "", "")

    record = execute_trial(target, "code-only", 1, "claude", None, mutating_agent, {"models": {}})

    assert record["status"] == "failed"
    assert "vulnerable/query.ts" in record["reason"]


def test_api_key_guard_requires_explicit_override(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENAI_API_KEY", "<REDACTED>")

    with pytest.raises(ValueError, match="--allow-api-key"):
        guard_api_keys(False)
    guard_api_keys(True)


def test_codex_command_uses_workspace_write_sandbox(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("eval.runner.subprocess.run", fake_run)
    command = default_agent_command({"models": {"codex": "test", "claude": "test"}})

    command(tmp_path, "codex", "scan")

    assert commands == [[
        "codex", "--model", "test", "exec", "--cd", str(tmp_path),
        "--sandbox", "workspace-write", "scan",
    ]]


def test_trial_skills_are_available_under_codex_project_convention(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source_skills = tmp_path / "source/skills/security-scan"
    source_skills.mkdir(parents=True)
    (source_skills / "SKILL.md").write_text("# scan\n")
    monkeypatch.setattr("eval.runner.REPO_ROOT", tmp_path / "source")

    install_trial_skills(tmp_path / "target")

    assert (tmp_path / "target/.agents/skills/security-scan/SKILL.md").read_text() == "# scan\n"


def test_usage_limit_marks_incomplete_then_resume_completes(tmp_path: Path):
    repo, _ = runner_repo(tmp_path)
    calls = 0

    def limited_agent(target: Path, agent: str, prompt: str) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess([agent], 1, "", "usage limit reached")

    results, first = run(
        RunOptions(tier="fast", results_dir=tmp_path / "results", baseline_check=False),
        agent_command=limited_agent,
        repo_root=repo,
    )
    assert first.exit_code == 2
    assert calls == 1

    _, resumed = run(
        RunOptions(tier="fast", resume_dir=results, baseline_check=False),
        agent_command=successful_agent,
        repo_root=repo,
    )
    assert resumed.exit_code == 0
    assert all(json.loads(path.read_text())["status"] == "ok" for path in (results / "trials").glob("*.json"))
