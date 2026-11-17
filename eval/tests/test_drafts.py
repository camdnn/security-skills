"""Draft ground truth and benchmark definitions stay well-formed until a human promotes them.

Drafts (`expected.draft.json`) are not scored, so nothing else would notice them
going stale; the evidence check against each benchmark's pinned clone runs in
`check-truth` once a draft becomes `expected.json`.
"""

import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from eval.runner import load_benchmark

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "eval/schemas/expected.schema.json").read_text())
FAMILIES = json.loads((ROOT / "eval/cwe_families.json").read_text())
DRAFTS = sorted(ROOT.glob("eval/benchmarks/*/expected.draft.json")) + sorted(ROOT.glob("tests/fixtures/*/expected.draft.json"))
BENCHMARKS = sorted(ROOT.glob("eval/benchmarks/*/benchmark.yaml"))
QUESTION_IDS = set(re.findall(r"^### (\S+) — ", (ROOT / "skills/security-context/references/question-bank.md").read_text(), re.MULTILINE))


@pytest.mark.parametrize("draft", DRAFTS, ids=lambda p: str(p.relative_to(ROOT)))
def test_draft_is_schema_valid_and_uses_registered_cwes(draft: Path):
    document = json.loads(draft.read_text())

    assert list(Draft202012Validator(SCHEMA).iter_errors(document)) == []
    assert [e["id"] for e in document["truth"] if e["cwe"] not in FAMILIES["cwe_to_family"]] == []
    ids = [entry["id"] for entry in document["truth"]]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("draft", DRAFTS, ids=lambda p: str(p.relative_to(ROOT)))
def test_draft_entries_in_one_file_and_family_are_far_apart(draft: Path):
    """§3.2: one vulnerability per location area, so the ±5-line tolerance can't blur two entries."""

    seen: dict[tuple[str, str], list[tuple[int, int, str]]] = {}
    for entry in json.loads(draft.read_text())["truth"]:
        family = FAMILIES["cwe_to_family"][entry["cwe"]]
        for location in entry["locations"]:
            seen.setdefault((location["file"], family), []).append((location["start_line"], location["end_line"], entry["id"]))
    clashes = [
        f"{a[2]} / {b[2]} in {file}"
        for (file, _), spans in seen.items()
        for i, a in enumerate(spans)
        for b in spans[i + 1:]
        if a[2] != b[2] and a[0] <= b[1] + 10 and b[0] <= a[1] + 10
    ]
    assert clashes == []


def test_juice_shop_draft_meets_the_q4_size():
    truth = json.loads((ROOT / "eval/benchmarks/juice-shop/expected.draft.json").read_text())["truth"]

    assert 25 <= len(truth) <= 30
    assert sum(entry["requires_context"] for entry in truth) >= 5


@pytest.mark.parametrize("definition", BENCHMARKS, ids=lambda p: p.parent.name)
def test_benchmark_definitions_load_and_their_answers_use_question_ids(definition: Path):
    target = load_benchmark(definition)

    assert target.answers_path is not None and target.answers_path.exists()
    answer_ids = re.findall(r"^## (\S+)\s*$", target.answers_path.read_text(), re.MULTILINE)
    assert answer_ids and [i for i in answer_ids if i not in QUESTION_IDS] == []
