"""Contract checks for the injection skill's public finding interface."""

from pathlib import Path

SKILL = (
    Path(__file__).resolve().parents[2] / "skills" / "injection-check" / "SKILL.md"
)


def test_injection_check_requires_full_findings_at_the_sink() -> None:
    skill = SKILL.read_text(encoding="utf-8")

    assert "../security-scan/references/finding-schema.json" in skill
    assert "A05:2025" in skill
    assert "source" in skill
    assert "sink" in skill
    assert "end_line" in skill
    assert "../security-scan/references/dread-rubric.md" in skill


def test_injection_check_preserves_the_safe_api_exclusions() -> None:
    skill = SKILL.read_text(encoding="utf-8")

    assert "parameterized" in skill
    assert "argument array" in skill
    assert "expression parser" in skill
