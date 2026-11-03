"""Tests for the trial findings validation boundary."""

import json
from pathlib import Path

import pytest

from eval.validate import validate_findings

DATA = Path(__file__).parent / "data"


def write_findings(path: Path, findings: list[dict]) -> Path:
    path.write_text(json.dumps(findings))
    return path


def test_valid_findings_file_is_accepted(tmp_path: Path):
    finding = json.loads((DATA / "finding-example.json").read_text())

    result = validate_findings(write_findings(tmp_path / "findings.json", [finding]))

    assert result.status == "ok"
    assert result.trial_status == "ok"
    assert result.findings == [finding]
    assert result.errors == []


def test_malformed_json_is_schema_invalid_without_raising(tmp_path: Path):
    findings_path = tmp_path / "findings.json"
    findings_path.write_text("{ not json")

    result = validate_findings(findings_path)

    assert result.status == "schema-invalid"
    assert result.trial_status == "failed"
    assert result.findings == []
    assert result.errors


def test_non_utf8_file_is_schema_invalid_without_raising(tmp_path: Path):
    findings_path = tmp_path / "findings.json"
    findings_path.write_bytes(b"\x80")

    result = validate_findings(findings_path)

    assert result.status == "schema-invalid"
    assert result.trial_status == "failed"
    assert result.findings == []
    assert result.errors


def test_finding_missing_required_field_is_schema_invalid(tmp_path: Path):
    finding = json.loads((DATA / "finding-example.json").read_text())
    del finding["evidence"]

    result = validate_findings(write_findings(tmp_path / "findings.json", [finding]))

    assert result.status == "schema-invalid"
    assert result.trial_status == "failed"
    assert "evidence" in result.errors[0]


@pytest.mark.parametrize("score", [4.3, 4.5])
def test_dread_score_must_equal_rounded_mean(tmp_path: Path, score: float):
    finding = json.loads((DATA / "finding-example.json").read_text())
    finding["dread"]["score"] = score

    result = validate_findings(write_findings(tmp_path / "findings.json", [finding]))

    assert result.status == "schema-invalid"
    assert result.trial_status == "failed"
    assert "DREAD score" in result.errors[0]


def test_finding_whose_end_line_precedes_its_line_is_schema_invalid(tmp_path: Path):
    finding = json.loads((DATA / "finding-example.json").read_text())
    finding["line"] = 50
    finding["end_line"] = 40

    result = validate_findings(write_findings(tmp_path / "findings.json", [finding]))

    assert result.status == "schema-invalid"
    assert result.trial_status == "failed"
    assert "end_line" in result.errors[0]
    assert "Finding 0" in result.errors[0]


def test_single_line_finding_is_accepted(tmp_path: Path):
    finding = json.loads((DATA / "finding-example.json").read_text())
    finding["end_line"] = finding["line"]

    result = validate_findings(write_findings(tmp_path / "findings.json", [finding]))

    assert result.status == "ok"
