"""Validate a trial's findings output without allowing malformed output to crash it."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[1]
FINDING_SCHEMA_PATH = REPO_ROOT / "skills/security-scan/references/finding-schema.json"
DREAD_FACTORS = (
    "damage",
    "reproducibility",
    "exploitability",
    "affected_users",
    "discoverability",
)


@dataclass(frozen=True)
class ValidationResult:
    """The validation outcome the runner uses to classify a trial."""

    status: Literal["ok", "schema-invalid"]
    trial_status: Literal["ok", "failed"]
    findings: list[dict[str, Any]]
    errors: list[str]


def validate_findings(findings_path: Path | str) -> ValidationResult:
    """Return a result for ``findings_path``; malformed output is schema-invalid.

    The findings schema remains the source of truth for finding structure. DREAD
    score arithmetic is checked here because JSON Schema cannot express it.
    """

    try:
        findings = json.loads(Path(findings_path).read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return schema_invalid(str(error))

    if not isinstance(findings, list):
        return schema_invalid("findings.json must contain a JSON array")

    try:
        schema = json.loads(FINDING_SCHEMA_PATH.read_text())
        validator = Draft202012Validator(schema)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return schema_invalid("Unable to load the finding schema")

    for index, finding in enumerate(findings):
        errors = sorted(validator.iter_errors(finding), key=lambda error: list(error.path))
        if errors:
            return schema_invalid(f"Finding {index}: {errors[0].message}")

        dread_error = validate_dread_score(finding)
        if dread_error:
            return schema_invalid(f"Finding {index}: {dread_error}")

    return ValidationResult(status="ok", trial_status="ok", findings=findings, errors=[])


def validate_dread_score(finding: dict[str, Any]) -> str | None:
    """Return an error when a schema-valid finding's DREAD score is incorrect."""

    dread = finding["dread"]
    expected_score = round(sum(dread[factor] for factor in DREAD_FACTORS) / len(DREAD_FACTORS), 1)
    if dread["score"] != expected_score:
        return f"DREAD score must be {expected_score}, got {dread['score']}"
    return None


def schema_invalid(error: str) -> ValidationResult:
    """Create the non-raising result for an invalid trial output."""

    return ValidationResult(
        status="schema-invalid",
        trial_status="failed",
        findings=[],
        errors=[error],
    )
