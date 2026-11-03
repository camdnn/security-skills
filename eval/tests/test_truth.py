"""Tests for verifying that ground-truth evidence still matches its target."""

import json
from pathlib import Path

from eval.truth import check_truth_file


def expected_document(file: str, start_line: int, end_line: int) -> dict:
    return {
        "truth": [
            {
                "id": "TEST-001",
                "cwe": "CWE-89",
                "locations": [
                    {"file": file, "start_line": start_line, "end_line": end_line}
                ],
                "evidence": "db.query(userInput)",
                "requires_context": False,
                "description": "Test injection",
                "source": "unit test",
            }
        ]
    }


def write_expected(target: Path, document: dict) -> Path:
    expected_path = target / "expected.json"
    expected_path.write_text(json.dumps(document))
    return expected_path


def test_correct_evidence_at_its_location_passes(tmp_path: Path):
    source = tmp_path / "routes" / "search.ts"
    source.parent.mkdir()
    source.write_text("line one\nline two\ndb.query(userInput)\n")
    expected_path = write_expected(tmp_path, expected_document("routes/search.ts", 3, 3))

    result = check_truth_file(expected_path, tmp_path)

    assert result.valid
    assert result.errors == []


def test_evidence_outside_its_declared_lines_fails_with_file_and_line(tmp_path: Path):
    source = tmp_path / "routes" / "search.ts"
    source.parent.mkdir()
    source.write_text("line one\nline two\ndb.query(userInput)\n")
    expected_path = write_expected(tmp_path, expected_document("routes/search.ts", 2, 2))

    result = check_truth_file(expected_path, tmp_path)

    assert not result.valid
    assert "routes/search.ts:2-2" in result.errors[0]


def test_missing_evidence_file_fails(tmp_path: Path):
    expected_path = write_expected(tmp_path, expected_document("routes/missing.ts", 1, 1))

    result = check_truth_file(expected_path, tmp_path)

    assert not result.valid
    assert "routes/missing.ts:1-1" in result.errors[0]
    assert "does not exist" in result.errors[0]


def test_schema_invalid_ground_truth_is_reported(tmp_path: Path):
    expected_path = write_expected(tmp_path, {"truth": [{"id": "missing fields"}]})

    result = check_truth_file(expected_path, tmp_path)

    assert not result.valid
    assert "schema-invalid" in result.errors[0]
