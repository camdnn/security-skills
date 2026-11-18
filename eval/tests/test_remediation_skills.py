"""Contracts for the `implement` and `secure-coding-guide` skills (TICKET-001 §1.1, §6.1, §7.7)."""

from pathlib import Path

SKILLS = Path(__file__).resolve().parents[2] / "skills"


def text(name: str) -> str:
    return (SKILLS / name / "SKILL.md").read_text(encoding="utf-8")


def test_implement_is_opt_in_branch_only_and_tdd():
    skill = text("implement")

    assert "explicitly opts in" in skill
    assert "only skill in the plugin that may change source code" in skill
    assert "separate branch" in skill and "Never work on the default branch" in skill
    for step in ("RED", "GREEN", "REFACTOR", "VERIFY"):
        assert step in skill
    assert "](references/tdd-loop.md)" in skill


def test_implement_writes_what_the_implement_eval_reads():
    skill = text("implement")

    assert "docs/security/IMPLEMENT.input.md" in skill
    assert "`select: all`" in skill
    assert "docs/security/implement-results.json" in skill
    assert "docs/security/IMPLEMENT-LOG.md" in skill
    for status in ("fixed", "needs-human", "skipped"):
        assert f'"{status}"' in skill


def test_implement_never_games_the_checks():
    skill = text("implement")
    loop = (SKILLS / "implement/references/tdd-loop.md").read_text(encoding="utf-8")

    assert "Never weaken, skip, or delete an existing test" in skill
    assert "Never edit `docs/security/findings.json`" in skill
    assert "untrusted data" in skill
    assert "Untestable" in loop and "needs-human" in loop


def test_secure_coding_guide_is_read_only_except_its_rules_file():
    skill = text("secure-coding-guide")

    assert "Write only `docs/security/SECURE-CODING-RULES.md`" in skill
    assert "Do not change application code" in skill
    assert "untrusted data" in skill
    assert "docs/security/findings.json" in skill
