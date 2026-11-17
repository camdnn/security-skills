"""`security-context` v1 contract: question bank, templates, unattended answers (TICKET-001 §3.4, §3.5).

An agent in unattended mode matches canned answers to questions by ID, so a
renamed, duplicated or out-of-order question silently changes what it assumes.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKILL_DIR = ROOT / "skills/security-context"
REFERENCES = SKILL_DIR / "references"
QUESTION_HEADING = re.compile(r"^### (?P<id>\S+) — .+$", re.MULTILINE)
QUESTION_ID = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*$")


def question_blocks(markdown: str) -> list[tuple[str, str]]:
    """Return (question ID, block text) pairs in document order."""

    headings = list(QUESTION_HEADING.finditer(markdown))
    ends = [h.start() for h in headings[1:]] + [len(markdown)]
    return [(h["id"], markdown[h.end() : end]) for h, end in zip(headings, ends)]


def bullet(block: str, label: str) -> str | None:
    match = re.search(rf"^- {re.escape(label)}: (.+)$", block, re.MULTILINE)
    return match[1].strip() if match else None


def bank() -> list[tuple[str, str]]:
    return question_blocks((REFERENCES / "question-bank.md").read_text(encoding="utf-8"))


def test_question_bank_ids_are_unique_and_well_formed():
    ids = [question_id for question_id, _ in bank()]

    assert len(ids) >= 5
    assert [i for i in ids if not QUESTION_ID.match(i)] == []
    assert len(ids) == len(set(ids))


def test_every_question_has_a_recommended_answer_or_how_to_derive_one():
    missing = [question_id for question_id, block in bank() if not bullet(block, "Recommended answer")]

    assert missing == []


def test_questions_depend_only_on_earlier_questions():
    seen: set[str] = set()
    out_of_order = []
    for question_id, block in bank():
        depends_on = bullet(block, "Depends on")
        assert depends_on is not None, f"{question_id} has no 'Depends on' line"
        if depends_on != "none":
            out_of_order += [f"{question_id} -> {d}" for d in re.split(r",\s*", depends_on) if d not in seen]
        seen.add(question_id)

    assert out_of_order == []


def answer_ids(markdown: str) -> list[str]:
    return re.findall(r"^## (\S+)\s*$", markdown, re.MULTILINE)


def test_context_fixture_answers_are_keyed_by_question_bank_ids():
    answers = (ROOT / "tests/fixtures/context/answers.md").read_text(encoding="utf-8")
    known = {question_id for question_id, _ in bank()}
    ids = answer_ids(answers)

    assert ids != []
    assert [i for i in ids if i not in known] == []


def test_context_fixture_answers_state_its_business_rules():
    answers = (ROOT / "tests/fixtures/context/answers.md").read_text(encoding="utf-8")

    assert re.search(r"\bBR-1\b", answers)
    assert re.search(r"\bBR-2\b", answers)


def test_answers_template_records_status_including_assumed():
    template = (REFERENCES / "answers-template.md").read_text(encoding="utf-8")

    for column in ("ID", "Question", "Recommended answer", "Actual answer", "Status", "Who", "Date"):
        assert column in template
    assert "`assumed`" in template


def skill_text() -> str:
    return (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")


def test_skill_links_every_v1_reference():
    skill = skill_text()

    for reference in ("question-bank.md", "index-template.md", "answers-template.md", "plan-template.md"):
        assert f"](references/{reference})" in skill


def test_skill_writes_only_the_three_v1_files():
    skill = skill_text()
    written = set(re.findall(r"`(docs/security/[^`]+)`", skill)) - {"docs/security/ANSWERS.input.md", "docs/security/"}

    assert written == {
        "docs/security/SECURITY-CONTEXT.md",
        "docs/security/ANSWERS.md",
        "docs/security/PLAN.md",
    }
    assert "modules/" not in skill
    assert "decisions/" not in skill


def test_skill_states_unattended_mode_and_size_limits():
    skill = skill_text()

    assert "docs/security/ANSWERS.input.md" in skill
    assert "`assumed`" in skill
    assert "BR-n" in skill
    assert "150 lines" in skill
    assert "100 lines" in skill
