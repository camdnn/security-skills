"""Replay, sandbox enforcement, and resume behavior for evaluation trials."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from eval.runner import (
    Agent,
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
        "context_file_line_limits:\n  SECURITY-CONTEXT.md: 150\n  PLAN.md: 100\n  modules/*.md: 200\n  decisions/*.md: 40\n"
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


def agent_commands_from_trial(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, agent: Agent) -> list[list[str]]:
    """Run one live code-only trial with the default command and return the agent calls it made."""
    _, target = runner_repo(tmp_path)
    real_run = subprocess.run
    commands: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[0] == "git":
            return real_run(command, **kwargs)  # type: ignore[call-overload,no-any-return]
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("eval.runner.subprocess.run", fake_run)
    config = {"models": {"claude": "claude-pinned", "codex": "codex-pinned"}}

    execute_trial(target, "code-only", 1, agent, None, None, config)

    return commands


def test_claude_trial_invokes_scan_slash_command_isolated_from_the_developer_machine(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    [command] = agent_commands_from_trial(monkeypatch, tmp_path, "claude")

    assert command[:3] == ["claude", "-p", "/analyzer:security-scan"]
    assert "--strict-mcp-config" in command
    assert "--mcp-config" not in command
    assert command[command.index("--setting-sources") + 1] == "project"
    assert command[command.index("--disallowedTools") + 1] == "WebFetch,WebSearch"
    assert command[command.index("--model") + 1] == "claude-pinned"


def test_codex_trial_keeps_a_plain_language_prompt_naming_the_skill(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    [command] = agent_commands_from_trial(monkeypatch, tmp_path, "codex")

    assert command[:5] == ["codex", "--model", "codex-pinned", "exec", "--cd"]
    assert Path(command[5]).name == "target"  # the trial copy, never the fixture
    assert command[6:8] == ["--sandbox", "workspace-write"]
    prompt = command[-1]
    assert "security-scan" in prompt
    assert not prompt.startswith("/")


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


def test_fast_run_uses_context_for_a_fixture_with_answers_and_copies_them(tmp_path: Path):
    repo, target = runner_repo(tmp_path)
    answers = target.root / "answers.md"
    answers.write_text("# Developer answers\n")
    seen_prompts: list[tuple[str, str]] = []

    def agent(root: Path, agent_name: str, prompt: str) -> subprocess.CompletedProcess[str]:
        seen_prompts.append((prompt, (root / "docs/security/ANSWERS.input.md").read_text() if (root / "docs/security/ANSWERS.input.md").exists() else ""))
        return successful_agent(root, agent_name, prompt)

    results, outcome = run(
        RunOptions(tier="fast", runs=1, results_dir=tmp_path / "results", baseline_check=False),
        agent_command=agent,
        repo_root=repo,
    )

    assert outcome.exit_code == 0
    assert [json.loads(path.read_text())["mode"] for path in (results / "trials").glob("*.json")] == ["context"]
    assert seen_prompts == [
        ("/analyzer:security-context", "# Developer answers\n"),
        ("/analyzer:security-scan", "# Developer answers\n"),
    ]


def test_fast_run_uses_code_only_for_a_fixture_without_answers(tmp_path: Path):
    repo, _ = runner_repo(tmp_path)
    prompts: list[str] = []

    def agent(root: Path, agent_name: str, prompt: str) -> subprocess.CompletedProcess[str]:
        prompts.append(prompt)
        return successful_agent(root, agent_name, prompt)

    results, _ = run(
        RunOptions(tier="fast", runs=1, results_dir=tmp_path / "results", baseline_check=False),
        agent_command=agent,
        repo_root=repo,
    )

    assert [json.loads(path.read_text())["mode"] for path in (results / "trials").glob("*.json")] == ["code-only"]
    assert prompts == ["/analyzer:security-scan"]


def test_mode_override_forces_code_only_for_a_fixture_with_answers(tmp_path: Path):
    repo, target = runner_repo(tmp_path)
    (target.root / "answers.md").write_text("# Developer answers\n")
    prompts: list[str] = []

    def agent(root: Path, agent_name: str, prompt: str) -> subprocess.CompletedProcess[str]:
        prompts.append(prompt)
        return successful_agent(root, agent_name, prompt)

    results, _ = run(
        RunOptions(tier="fast", mode="code-only", runs=1, results_dir=tmp_path / "results", baseline_check=False),
        agent_command=agent,
        repo_root=repo,
    )

    assert [json.loads(path.read_text())["mode"] for path in (results / "trials").glob("*.json")] == ["code-only"]
    assert prompts == ["/analyzer:security-scan"]


def test_full_run_uses_both_modes_for_a_fixture_with_answers(tmp_path: Path):
    repo, target = runner_repo(tmp_path)
    (target.root / "answers.md").write_text("# Developer answers\n")
    prompts: list[str] = []

    def agent(root: Path, agent_name: str, prompt: str) -> subprocess.CompletedProcess[str]:
        prompts.append(prompt)
        return successful_agent(root, agent_name, prompt)

    results, _ = run(
        RunOptions(tier="full", runs=1, results_dir=tmp_path / "results", baseline_check=False),
        agent_command=agent,
        repo_root=repo,
    )

    assert sorted(json.loads(path.read_text())["mode"] for path in (results / "trials").glob("*.json")) == ["code-only", "context"]
    assert prompts == [
        "Run security-scan and write findings to docs/security/findings.json.",
        "Run security-context unattended, using docs/security/ANSWERS.input.md when present.",
        "Run security-scan and write findings to docs/security/findings.json.",
    ]


def test_skill_run_selects_fixture_by_its_ground_truth_family_not_folder_name(tmp_path: Path):
    repo, target = runner_repo(tmp_path)
    (repo / "eval/cwe_families.json").write_text(json.dumps({
        "cwe_to_family": {"CWE-862": "access-control"},
        "families": {"access-control": "access-control-check"},
    }))
    renamed = target.root.parent / "misleading-fixture"
    target.root.rename(renamed)
    (renamed / "expected.json").write_text(json.dumps({
        "truth": [{**expected()["truth"][0], "cwe": "CWE-862"}],
        "must_not_find": [],
    }))

    results, _ = run(
        RunOptions(
            tier="fast",
            skill="access-control-check",
            runs=1,
            results_dir=tmp_path / "results",
            baseline_check=False,
        ),
        agent_command=successful_agent,
        repo_root=repo,
    )

    assert [json.loads(path.read_text())["target"] for path in (results / "trials").glob("*.json")] == ["misleading-fixture"]


def test_skill_run_selects_fixture_by_must_not_find_family(tmp_path: Path):
    repo, target = runner_repo(tmp_path)
    (repo / "eval/cwe_families.json").write_text(json.dumps({
        "cwe_to_family": {},
        "families": {"access-control": "access-control-check"},
    }))
    (target.root / "expected.json").write_text(json.dumps({
        "truth": [],
        "must_not_find": [{"file": "safe/example.ts", "cwe_family": "access-control"}],
    }))

    def agent(root: Path, agent_name: str, prompt: str) -> subprocess.CompletedProcess[str]:
        output = root / "docs/security/findings.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("[]")
        return subprocess.CompletedProcess([agent_name], 0, "", "")

    results, _ = run(
        RunOptions(
            tier="fast",
            skill="access-control-check",
            runs=1,
            results_dir=tmp_path / "results",
            baseline_check=False,
        ),
        agent_command=agent,
        repo_root=repo,
    )

    assert [json.loads(path.read_text())["target"] for path in (results / "trials").glob("*.json")] == ["injection-check"]


def test_context_trial_reports_an_oversized_context_file_without_failing(tmp_path: Path):
    repo, _ = runner_repo(tmp_path)

    def agent(root: Path, agent_name: str, prompt: str) -> subprocess.CompletedProcess[str]:
        if "security-context" in prompt:
            context = root / "docs/security/SECURITY-CONTEXT.md"
            context.parent.mkdir(parents=True, exist_ok=True)
            context.write_text("line\n" * 151)
        return successful_agent(root, agent_name, prompt)

    results, outcome = run(
        RunOptions(tier="fast", mode="context", runs=1, results_dir=tmp_path / "results", baseline_check=False),
        agent_command=agent,
        repo_root=repo,
    )

    record = json.loads(next((results / "trials").glob("*.json")).read_text())
    assert outcome.exit_code == 0
    assert record["status"] == "ok"
    assert record["warnings"] == [{"file": "docs/security/SECURITY-CONTEXT.md", "limit": 150, "lines": 151}]
    assert "docs/security/SECURITY-CONTEXT.md: 151 lines (limit 150)" in (results / "report.md").read_text()


def test_context_trial_omits_warnings_when_context_files_fit_within_limits(tmp_path: Path):
    repo, _ = runner_repo(tmp_path)

    def agent(root: Path, agent_name: str, prompt: str) -> subprocess.CompletedProcess[str]:
        if "security-context" in prompt:
            plan = root / "docs/security/PLAN.md"
            plan.parent.mkdir(parents=True, exist_ok=True)
            plan.write_text("line\n" * 100)
        return successful_agent(root, agent_name, prompt)

    results, _ = run(
        RunOptions(tier="fast", mode="context", runs=1, results_dir=tmp_path / "results", baseline_check=False),
        agent_command=agent,
        repo_root=repo,
    )

    record = json.loads(next((results / "trials").glob("*.json")).read_text())
    assert "warnings" not in record
    assert "## Warnings\n\nNone." in (results / "report.md").read_text()


def test_code_only_trial_does_not_measure_context_files(tmp_path: Path):
    repo, _ = runner_repo(tmp_path)

    def agent(root: Path, agent_name: str, prompt: str) -> subprocess.CompletedProcess[str]:
        context = root / "docs/security/SECURITY-CONTEXT.md"
        context.parent.mkdir(parents=True, exist_ok=True)
        context.write_text("line\n" * 151)
        return successful_agent(root, agent_name, prompt)

    results, _ = run(
        RunOptions(tier="fast", mode="code-only", runs=1, results_dir=tmp_path / "results", baseline_check=False),
        agent_command=agent,
        repo_root=repo,
    )

    record = json.loads(next((results / "trials").glob("*.json")).read_text())
    assert "warnings" not in record
    assert "## Warnings\n\nNone." in (results / "report.md").read_text()


def test_context_trial_does_not_warn_for_an_oversized_preexisting_context_file(tmp_path: Path):
    repo, target = runner_repo(tmp_path)
    context = target.root / "docs/security/SECURITY-CONTEXT.md"
    context.parent.mkdir(parents=True)
    context.write_text("line\n" * 151)

    results, _ = run(
        RunOptions(tier="fast", mode="context", runs=1, results_dir=tmp_path / "results", baseline_check=False),
        agent_command=successful_agent,
        repo_root=repo,
    )

    record = json.loads(next((results / "trials").glob("*.json")).read_text())
    assert "warnings" not in record
    assert "## Warnings\n\nNone." in (results / "report.md").read_text()


def test_context_trial_hides_ground_truth_and_exposes_answers_only_as_input(tmp_path: Path):
    repo, target = runner_repo(tmp_path)
    (target.root / "answers.md").write_text("# Developer answers\n")
    seen: list[tuple[bool, bool, str]] = []

    def agent(root: Path, agent_name: str, prompt: str) -> subprocess.CompletedProcess[str]:
        answers_input = root / "docs/security/ANSWERS.input.md"
        seen.append((
            (root / "expected.json").exists(),
            (root / "answers.md").exists(),
            answers_input.read_text() if answers_input.exists() else "",
        ))
        return successful_agent(root, agent_name, prompt)

    _, outcome = run(
        RunOptions(tier="fast", mode="context", runs=1, results_dir=tmp_path / "results", baseline_check=False),
        agent_command=agent,
        repo_root=repo,
    )

    assert outcome.exit_code == 0
    assert seen == [(False, False, "# Developer answers\n"), (False, False, "# Developer answers\n")]


def test_code_only_trial_hides_fixture_answers_and_ground_truth(tmp_path: Path):
    repo, target = runner_repo(tmp_path)
    (target.root / "answers.md").write_text("# Developer answers\n")
    seen: list[tuple[bool, bool, bool]] = []

    def agent(root: Path, agent_name: str, prompt: str) -> subprocess.CompletedProcess[str]:
        seen.append((
            (root / "expected.json").exists(),
            (root / "answers.md").exists(),
            (root / "docs/security/ANSWERS.input.md").exists(),
        ))
        return successful_agent(root, agent_name, prompt)

    _, outcome = run(
        RunOptions(tier="fast", mode="code-only", runs=1, results_dir=tmp_path / "results", baseline_check=False),
        agent_command=agent,
        repo_root=repo,
    )

    assert outcome.exit_code == 0
    assert seen == [(False, False, False)]
