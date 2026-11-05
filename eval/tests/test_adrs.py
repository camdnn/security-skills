"""ADR files in docs/adr/ are numbered uniquely and without gaps (TICKET-001 §0 rule 12)."""

import re
from pathlib import Path

ADR_DIR = Path(__file__).resolve().parents[2] / "docs/adr"
ADR_NAME = re.compile(r"(\d{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.md")


def test_every_adr_file_is_named_number_dash_slug():
    names = sorted(path.name for path in ADR_DIR.iterdir())

    assert [name for name in names if not ADR_NAME.fullmatch(name)] == []


def test_adr_numbers_are_unique_and_consecutive_from_one():
    """Two branches that each add the next ADR collide here after the second merges."""
    numbers = sorted(int(m[1]) for path in ADR_DIR.iterdir() if (m := ADR_NAME.fullmatch(path.name)))

    assert numbers == list(range(1, len(numbers) + 1))
