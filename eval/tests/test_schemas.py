"""The finding and ground-truth schemas accept the TICKET-001 §3.1/§3.2 examples
and reject documents that break the locked contract."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPO = Path(__file__).resolve().parents[2]
DATA = Path(__file__).parent / "data"
FINDING_SCHEMA = REPO / "skills/security-scan/references/finding-schema.json"
GROUND_TRUTH_SCHEMA = REPO / "eval/schemas/expected.schema.json"


def load(path: Path):
    return json.loads(path.read_text())


def validator(schema_path: Path) -> Draft202012Validator:
    schema = load(schema_path)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


@pytest.fixture(scope="module")
def finding_validator():
    return validator(FINDING_SCHEMA)


@pytest.fixture(scope="module")
def ground_truth_validator():
    return validator(GROUND_TRUTH_SCHEMA)


@pytest.fixture
def finding():
    return load(DATA / "finding-example.json")


def test_finding_example_is_valid(finding_validator, finding):
    finding_validator.validate(finding)


def test_finding_without_data_flow_or_business_rule_is_valid(finding_validator, finding):
    finding["trace"] = []
    finding["context_ref"] = None
    finding_validator.validate(finding)


@pytest.mark.parametrize(
    "field, value",
    [
        ("mode", "unattended"),
        ("mode", "code_only"),
        ("confidence", "certain"),
        ("confidence", "High"),
    ],
)
def test_finding_rejects_values_outside_locked_enums(finding_validator, finding, field, value):
    finding[field] = value
    assert not finding_validator.is_valid(finding)


@pytest.mark.parametrize("value", [0, 6, 4.5])
def test_finding_rejects_dread_factor_outside_1_to_5_integers(finding_validator, finding, value):
    finding["dread"]["damage"] = value
    assert not finding_validator.is_valid(finding)


def test_finding_rejects_missing_required_field(finding_validator, finding):
    del finding["evidence"]
    assert not finding_validator.is_valid(finding)


@pytest.fixture
def ground_truth():
    return load(DATA / "expected-example.json")


def test_ground_truth_example_is_valid(ground_truth_validator, ground_truth):
    ground_truth_validator.validate(ground_truth)


def test_truth_entry_rejects_category(ground_truth_validator, ground_truth):
    ground_truth["truth"][0]["category"] = "access-control"
    assert not ground_truth_validator.is_valid(ground_truth)


def test_truth_entry_requires_evidence(ground_truth_validator, ground_truth):
    del ground_truth["truth"][0]["evidence"]
    assert not ground_truth_validator.is_valid(ground_truth)


def test_truth_entry_requires_at_least_one_location(ground_truth_validator, ground_truth):
    ground_truth["truth"][0]["locations"] = []
    assert not ground_truth_validator.is_valid(ground_truth)


@pytest.mark.parametrize(
    "rule",
    [
        {"file": "safe/query.ts"},
        {"cwe_family": "injection"},
        {"file": "safe/query.ts", "cwe": "CWE-89"},
        {"file": "safe/query.ts", "cwe_family": "injection", "line": 3},
    ],
)
def test_must_not_find_rule_is_exactly_file_and_cwe_family(ground_truth_validator, ground_truth, rule):
    ground_truth["must_not_find"] = [rule]
    assert not ground_truth_validator.is_valid(ground_truth)


def test_finding_schema_has_no_other_copy_in_repo():
    schema_id = load(FINDING_SCHEMA)["$id"]
    skip = {".git", ".venv", "node_modules"}
    copies = [
        p.relative_to(REPO)
        for p in REPO.rglob("*.json")
        if not skip.intersection(p.relative_to(REPO).parts)
        and p != FINDING_SCHEMA
        and (p.name == FINDING_SCHEMA.name or schema_id in p.read_text())
    ]
    assert copies == []
