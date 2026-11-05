"""Verify that checked-in ground truth still points at vulnerable code."""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SCHEMA_PATH = REPO_ROOT / "eval/schemas/expected.schema.json"
CWE_FAMILIES_PATH = REPO_ROOT / "eval/cwe_families.json"


@dataclass(frozen=True)
class TruthCheckResult:
    """The reported outcome of checking one or more ground-truth files."""

    valid: bool
    errors: list[str]


def check_truth_file(expected_path: Path | str, target_root: Path | str) -> TruthCheckResult:
    """Validate one ground-truth file and verify every entry's evidence quote."""

    expected_path = Path(expected_path)
    target_root = Path(target_root).resolve()
    try:
        document = json.loads(expected_path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return invalid(f"{expected_path}: cannot read ground truth: {error}")

    validator = expected_validator()
    schema_errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if schema_errors:
        return invalid(f"{expected_path}: schema-invalid: {schema_errors[0].message}")

    errors: list[str] = []
    validate_registry_references(document, errors)
    for entry in document["truth"]:
        evidence_in_any_location(entry, target_root, errors)

    return TruthCheckResult(valid=not errors, errors=errors)


def check_all_truth(repo_root: Path | str = REPO_ROOT) -> TruthCheckResult:
    """Check every fixture and benchmark ground-truth file in the repository."""

    repo_root = Path(repo_root).resolve()
    results = [
        check_truth_file(expected_path, expected_path.parent)
        for expected_path in (repo_root / "tests/fixtures").glob("**/expected.json")
    ]
    results.extend(check_benchmark_truth(expected_path) for expected_path in (repo_root / "eval/benchmarks").glob("*/expected.json"))
    errors = [error for result in results for error in result.errors]
    return TruthCheckResult(valid=not errors, errors=errors)


def expected_validator() -> Draft202012Validator:
    """Load the canonical expected-schema file instead of copying its contract."""

    schema = json.loads(EXPECTED_SCHEMA_PATH.read_text())
    return Draft202012Validator(schema)


def validate_registry_references(document: dict[str, Any], errors: list[str]) -> None:
    """Reject unknown CWE data and rules that make a truth entry unmatchable."""

    registry = json.loads(CWE_FAMILIES_PATH.read_text())
    cwe_to_family = registry["cwe_to_family"]
    families = registry["families"]
    entries_by_location: dict[tuple[str, str], list[str]] = {}

    for entry in document["truth"]:
        family = cwe_to_family.get(entry["cwe"])
        if family is None:
            errors.append(f"truth {entry['id']}: {entry['cwe']} is not registered")
            continue
        for location in entry["locations"]:
            entries_by_location.setdefault((location["file"], family), []).append(entry["id"])

    for rule in document.get("must_not_find", []):
        family = rule["cwe_family"]
        rule_name = f"must-not-find rule {rule['file']} ({family})"
        if family not in families:
            errors.append(f"{rule_name}: family is not registered")
            continue
        for entry_id in entries_by_location.get((rule["file"], family), []):
            errors.append(f"truth {entry_id} contradicts {rule_name}")


def evidence_in_any_location(entry: dict[str, Any], target_root: Path, errors: list[str]) -> bool:
    """Append one useful diagnostic only when no allowed location contains evidence."""

    location_errors = [
        evidence_location_error(entry["evidence"], location, target_root)
        for location in entry["locations"]
    ]
    if None in location_errors:
        return True

    location_text = "; ".join(error for error in location_errors if error is not None)
    errors.append(f"truth {entry['id']}: {location_text}")
    return False


def evidence_location_error(evidence: str, location: dict[str, Any], target_root: Path) -> str | None:
    """Return a location-specific problem, or ``None`` when evidence is present."""

    display_location = f"{location['file']}:{location['start_line']}-{location['end_line']}"
    source_path = (target_root / location["file"]).resolve()
    try:
        source_path.relative_to(target_root)
    except ValueError:
        return f"{display_location} escapes the target root"

    try:
        source_lines = source_path.read_text().splitlines()
    except FileNotFoundError:
        return f"{display_location} does not exist"
    except (OSError, UnicodeError) as error:
        return f"{display_location} cannot be read: {error}"

    excerpt = "\n".join(source_lines[location["start_line"] - 1 : location["end_line"]])
    if evidence in excerpt:
        return None
    return f"evidence not found in {display_location}"


def check_benchmark_truth(expected_path: Path) -> TruthCheckResult:
    """Check a benchmark against a temporary checkout at its declared commit."""

    benchmark_path = expected_path.parent
    config_path = benchmark_path / "benchmark.yaml"
    try:
        config = yaml.safe_load(config_path.read_text())
        repository = config["repo"]
        commit = config["commit"]
    except (OSError, UnicodeError, KeyError, TypeError, yaml.YAMLError) as error:
        return invalid(f"{expected_path}: cannot read benchmark configuration: {error}")

    with tempfile.TemporaryDirectory(prefix="check-truth-") as temporary_directory:
        target_root = Path(temporary_directory) / "target"
        try:
            subprocess.run(
                ["git", "clone", "--quiet", repository, str(target_root)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "-C", str(target_root), "checkout", "--quiet", commit],
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            return invalid(f"{expected_path}: cannot check out pinned benchmark commit: {error}")
        return check_truth_file(expected_path, target_root)


def invalid(error: str) -> TruthCheckResult:
    return TruthCheckResult(valid=False, errors=[error])
