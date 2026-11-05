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


def test_unregistered_truth_cwe_fails_with_the_entry_id(tmp_path: Path):
    source = tmp_path / "routes" / "search.ts"
    source.parent.mkdir()
    source.write_text("db.query(userInput)\n")
    document = expected_document("routes/search.ts", 1, 1)
    document["truth"][0]["cwe"] = "CWE-999999"

    result = check_truth_file(write_expected(tmp_path, document), tmp_path)

    assert not result.valid
    assert any("TEST-001" in error and "CWE-999999" in error for error in result.errors)


def test_unknown_must_not_find_family_fails_with_the_rule_file(tmp_path: Path):
    source = tmp_path / "routes" / "search.ts"
    source.parent.mkdir()
    source.write_text("db.query(userInput)\n")
    document = expected_document("routes/search.ts", 1, 1)
    document["must_not_find"] = [{"file": "safe/query.ts", "cwe_family": "not-a-family"}]

    result = check_truth_file(write_expected(tmp_path, document), tmp_path)

    assert not result.valid
    assert any("safe/query.ts" in error and "not-a-family" in error for error in result.errors)


def test_must_not_find_rule_cannot_contradict_truth_entry(tmp_path: Path):
    source = tmp_path / "routes" / "search.ts"
    source.parent.mkdir()
    source.write_text("db.query(userInput)\n")
    document = expected_document("routes/search.ts", 1, 1)
    document["must_not_find"] = [{"file": "routes/search.ts", "cwe_family": "injection"}]

    result = check_truth_file(write_expected(tmp_path, document), tmp_path)

    assert not result.valid
    assert any("TEST-001" in error and "must-not-find rule routes/search.ts" in error for error in result.errors)
