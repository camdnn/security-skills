"""Every relative link in a skill's Markdown resolves to a file (TICKET-001 §6.1).

An agent told to read a missing reference file runs the trial without it, so a
broken link silently changes what the scan does.
"""

import re
from pathlib import Path

SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"
MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


def relative_link_targets(markdown: Path) -> list[str]:
    targets = (m[1] for m in MARKDOWN_LINK.finditer(markdown.read_text(encoding="utf-8")))
    return [t.split("#", 1)[0] for t in targets if not re.match(r"[a-z][a-z0-9+.-]*:|#", t)]


def test_every_relative_link_in_a_skill_resolves_to_a_file():
    broken = [
        f"{markdown.relative_to(SKILLS_DIR)} -> {target}"
        for markdown in sorted(SKILLS_DIR.rglob("*.md"))
        for target in relative_link_targets(markdown)
        if not (markdown.parent / target).is_file()
    ]

    assert broken == []
