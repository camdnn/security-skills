"""One-to-one matching of findings to truth entries (TICKET-001 §7.4, §7.6)."""

import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from eval.matcher import CONFIDENCE_RANK, Duplicate, load_tolerance, match

DATA = Path(__file__).parent / "data"
REPO = Path(__file__).resolve().parents[2]
TARGET_ROOT = "/target"


def load(name: str) -> dict:
    return json.loads((DATA / name).read_text())


@pytest.fixture
def truth() -> dict:
    return load("matcher-truth.json")


def finding(file="routes/search.ts", line=40, end_line=None, cwe="CWE-89", confidence="high", id="SEC-0001"):
    return load("finding-example.json") | {
        "id": id,
        "file": file,
        "line": line,
        "end_line": line if end_line is None else end_line,
        "cwe": cwe,
        "confidence": confidence,
    }


def ids(entries) -> list[str]:
    return [entry["id"] for entry in entries]


def truth_with_second_sqli_entry() -> dict:
    """SQLI-01 at lines 40-48 and SQLI-02 at 56-58: close enough to share findings."""
    truth = load("matcher-truth.json")
    truth["truth"][1] = truth["truth"][0] | {
        "id": "SQLI-02",
        "locations": [{"file": "routes/search.ts", "start_line": 56, "end_line": 58}],
    }
    return truth


def truth_with_small_and_large_sqli_locations() -> dict:
    """SQLI-01 at lines 10-12 (fits findings up to 13 lines) or 20-40 (up to 31) of one file."""
    truth = load("matcher-truth.json")
    truth["truth"][0]["locations"] = [
        {"file": "routes/search.ts", "start_line": 10, "end_line": 12},
        {"file": "routes/search.ts", "start_line": 20, "end_line": 40},
    ]
    return truth


def test_matcher_data_is_valid_ground_truth(truth):
    schema = json.loads((REPO / "eval/schemas/expected.schema.json").read_text())
    Draft202012Validator(schema).validate(truth)


def test_exact_location_is_a_match_and_other_entries_are_false_negatives(truth):
    found = finding(line=40, end_line=48)

    result = match([found], truth, TARGET_ROOT)

    assert [(m.finding["id"], m.entry["id"]) for m in result.matches] == [("SEC-0001", "SQLI-01")]
    assert ids(result.false_negatives) == ["IDOR-01"]
    assert result.duplicates == []
    assert result.false_positives == []


@pytest.mark.parametrize(
    "line, end_line",
    [
        pytest.param(51, 51, id="off by 3 below the location"),
        pytest.param(37, 37, id="off by 3 above the location"),
        pytest.param(53, 53, id="at the tolerance below"),
        pytest.param(35, 35, id="at the tolerance above"),
        pytest.param(30, 35, id="range ending at the tolerance"),
        pytest.param(44, 44, id="inside the location"),
    ],
)
def test_lines_within_tolerance_match(truth, line, end_line):
    result = match([finding(line=line, end_line=end_line)], truth, TARGET_ROOT)
    assert ids(m.entry for m in result.matches) == ["SQLI-01"]


@pytest.mark.parametrize(
    "line, end_line",
    [
        pytest.param(54, 54, id="off by 6 below the location"),
        pytest.param(34, 34, id="off by 6 above the location"),
        pytest.param(30, 34, id="range ending off by 6"),
    ],
)
def test_lines_outside_tolerance_are_a_false_positive_and_false_negative(truth, line, end_line):
    found = finding(line=line, end_line=end_line)

    result = match([found], truth, TARGET_ROOT)

    assert result.matches == []
    assert [fp.finding for fp in result.false_positives] == [found]
    assert ids(result.false_negatives) == ["SQLI-01", "IDOR-01"]


def test_finding_without_end_line_is_treated_as_a_single_line(truth):
    found = finding(line=53) | {"end_line": None}
    assert ids(m.entry for m in match([found], truth, TARGET_ROOT).matches) == ["SQLI-01"]


def test_wrong_cwe_family_does_not_match(truth):
    found = finding(cwe="CWE-79")

    result = match([found], truth, TARGET_ROOT)

    assert result.matches == []
    assert [fp.finding for fp in result.false_positives] == [found]


def test_same_family_with_a_different_cwe_matches(truth):
    result = match([finding(cwe="CWE-78")], truth, TARGET_ROOT)
    assert ids(m.entry for m in result.matches) == ["SQLI-01"]


def test_wrong_file_does_not_match(truth):
    result = match([finding(file="routes/other.ts")], truth, TARGET_ROOT)
    assert result.matches == []


@pytest.mark.parametrize(
    "file, line",
    [("routes/order.ts", 11), ("lib/orders.ts", 71)],
)
def test_entry_matches_at_any_of_its_locations(truth, file, line):
    result = match([finding(file=file, line=line, cwe="CWE-639")], truth, TARGET_ROOT)
    assert ids(m.entry for m in result.matches) == ["IDOR-01"]


def test_line_range_of_one_location_does_not_apply_to_another_file(truth):
    result = match([finding(file="lib/orders.ts", line=11, cwe="CWE-639")], truth, TARGET_ROOT)
    assert result.matches == []


def test_two_findings_for_one_entry_are_one_match_and_one_duplicate(truth):
    closer = finding(line=44, id="SEC-0001")
    further = finding(line=52, id="SEC-0002")

    result = match([further, closer], truth, TARGET_ROOT)

    assert [m.finding["id"] for m in result.matches] == ["SEC-0001"]
    assert [(d.finding["id"], d.entry["id"]) for d in result.duplicates] == [("SEC-0002", "SQLI-01")]
    assert result.false_positives == []


def test_equally_close_findings_go_to_the_higher_confidence_one(truth):
    low = finding(line=44, confidence="low", id="SEC-0001")
    medium = finding(line=45, confidence="medium", id="SEC-0002")
    high = finding(line=46, confidence="high", id="SEC-0003")

    result = match([low, medium, high], truth, TARGET_ROOT)

    assert [m.finding["id"] for m in result.matches] == ["SEC-0003"]
    assert [d.finding["id"] for d in result.duplicates] == ["SEC-0001", "SEC-0002"]


def test_closer_line_beats_higher_confidence(truth):
    close_low = finding(line=44, confidence="low", id="SEC-0001")
    far_high = finding(line=50, confidence="high", id="SEC-0002")

    result = match([far_high, close_low], truth, TARGET_ROOT)

    assert [m.finding["id"] for m in result.matches] == ["SEC-0001"]


def test_finding_in_range_of_two_entries_takes_the_closer_one():
    truth = truth_with_second_sqli_entry()

    # Reversed input order must not let the finding match the further entry.
    result = match([finding(line=51)], {"truth": truth["truth"][::-1]}, TARGET_ROOT)

    assert ids(m.entry for m in result.matches) == ["SQLI-01"]
    assert ids(result.false_negatives) == ["SQLI-02"]


def test_nearby_findings_each_take_their_closest_entry():
    truth = truth_with_second_sqli_entry()
    near_first = finding(line=51, id="SEC-0001")
    near_second = finding(line=53, id="SEC-0002")

    result = match([near_second, near_first], truth, TARGET_ROOT)

    assert {(m.finding["id"], m.entry["id"]) for m in result.matches} == {
        ("SEC-0001", "SQLI-01"),
        ("SEC-0002", "SQLI-02"),
    }
    assert result.duplicates == []


def test_empty_findings_make_every_entry_a_false_negative(truth):
    result = match([], truth, TARGET_ROOT)

    assert ids(result.false_negatives) == ["SQLI-01", "IDOR-01"]
    assert result.matches == result.duplicates == result.false_positives == []


def test_must_not_find_hit_is_a_flagged_false_positive(truth):
    found = finding(file="safe/query.ts", line=3)

    result = match([found], truth, TARGET_ROOT)

    assert result.matches == []
    assert [(fp.finding, fp.must_not_find_rule) for fp in result.false_positives] == [
        (found, {"file": "safe/query.ts", "cwe_family": "injection"})
    ]


def test_must_not_find_hit_applies_to_any_cwe_in_the_family(truth):
    result = match([finding(file="safe/query.ts", cwe="CWE-78")], truth, TARGET_ROOT)
    assert result.false_positives[0].must_not_find_rule is not None


@pytest.mark.parametrize(
    "found",
    [
        pytest.param(finding(file="safe/query.ts", cwe="CWE-79"), id="other family in the safe file"),
        pytest.param(finding(file="routes/other.ts"), id="same family in another file"),
    ],
)
def test_other_false_positives_are_not_flagged(truth, found):
    result = match([found], truth, TARGET_ROOT)

    assert [fp.finding for fp in result.false_positives] == [found]
    assert result.false_positives[0].must_not_find_rule is None


def test_must_not_find_rule_beats_a_truth_entry_in_the_same_place(truth):
    truth["must_not_find"].append({"file": "routes/search.ts", "cwe_family": "injection"})

    result = match([finding(line=40)], truth, TARGET_ROOT)

    assert result.matches == []
    assert result.false_positives[0].must_not_find_rule is not None
    assert "SQLI-01" in ids(result.false_negatives)


def test_ground_truth_without_must_not_find_is_accepted(truth):
    del truth["must_not_find"]
    result = match([finding(file="safe/query.ts")], truth, TARGET_ROOT)
    assert result.false_positives[0].must_not_find_rule is None


@pytest.mark.parametrize(
    "file",
    [
        "./routes/search.ts",
        "routes\\search.ts",
        "routes//extra/../search.ts",
        f"{TARGET_ROOT}/routes/search.ts",
    ],
)
def test_finding_paths_are_normalized_relative_to_the_target_root(truth, file):
    result = match([finding(file=file)], truth, TARGET_ROOT)
    assert ids(m.entry for m in result.matches) == ["SQLI-01"]


def test_ground_truth_paths_are_normalized_too(truth):
    truth["truth"][0]["locations"][0]["file"] = "./routes\\search.ts"
    result = match([finding()], truth, TARGET_ROOT)
    assert ids(m.entry for m in result.matches) == ["SQLI-01"]


def test_absolute_path_is_resolved_through_a_symlinked_target_root(truth, tmp_path):
    real_root = tmp_path / "real"
    real_root.mkdir()
    link_root = tmp_path / "link"
    link_root.symlink_to(real_root)

    found = finding(file=str(real_root / "routes/search.ts"))

    assert match([found], truth, str(link_root)).matches


def test_absolute_path_outside_the_target_root_does_not_match(truth):
    result = match([finding(file="/elsewhere/routes/search.ts")], truth, TARGET_ROOT)
    assert result.matches == []


def test_path_case_is_ignored_only_on_case_insensitive_systems(truth):
    found = finding(file="Routes/SEARCH.ts")

    assert match([found], truth, TARGET_ROOT, case_insensitive=True).matches
    assert not match([found], truth, TARGET_ROOT, case_insensitive=False).matches


def test_absolute_path_with_different_case_on_case_insensitive_systems(truth):
    found = finding(file=f"{TARGET_ROOT.upper()}/routes/search.ts")
    assert match([found], truth, TARGET_ROOT, case_insensitive=True).matches


def test_tolerance_argument_widens_and_narrows_the_match(truth):
    found = finding(line=54)

    assert match([found], truth, TARGET_ROOT, tolerance=6).matches
    assert not match([finding(line=49)], truth, TARGET_ROOT, tolerance=0).matches


def test_shipped_config_sets_the_locked_tolerance():
    assert load_tolerance() == 5


def test_tolerance_is_read_from_the_config_file(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("line_tolerance: 9\n")
    assert load_tolerance(config) == 9


@pytest.mark.parametrize("contents", [None, "", "trials: 3\n", "line_tolerance:\n"])
def test_tolerance_defaults_to_5_when_config_does_not_set_it(tmp_path, contents):
    config = tmp_path / "config.yaml"
    if contents is not None:
        config.write_text(contents)
    assert load_tolerance(config) == 5


def test_finding_with_a_cwe_outside_the_registry_is_a_false_positive(truth):
    found = finding(cwe="CWE-999999")

    result = match([found], truth, TARGET_ROOT)

    assert result.matches == []
    assert [fp.finding for fp in result.false_positives] == [found]


def test_truth_entry_with_a_cwe_outside_the_registry_is_rejected(truth):
    truth["truth"][0]["cwe"] = "CWE-999999"
    with pytest.raises(ValueError, match="SQLI-01.*CWE-999999"):
        match([], truth, TARGET_ROOT)


def test_must_not_find_rule_with_an_unknown_family_is_rejected(truth):
    truth["must_not_find"][0]["cwe_family"] = "injections"
    with pytest.raises(ValueError, match="injections"):
        match([], truth, TARGET_ROOT)


def test_duplicate_is_reported_as_its_own_kind_of_result(truth):
    result = match([finding(line=44), finding(line=45)], truth, TARGET_ROOT)
    assert [type(d) for d in result.duplicates] == [Duplicate]


def test_symlink_inside_the_target_does_not_change_an_absolute_path(truth, tmp_path):
    (tmp_path / "lib").mkdir()
    (tmp_path / "routes").symlink_to(tmp_path / "lib")

    found = finding(file=str(tmp_path / "routes/search.ts"))

    assert match([found], truth, str(tmp_path)).matches


def test_every_schema_confidence_has_a_rank():
    schema = json.loads((REPO / "skills/security-scan/references/finding-schema.json").read_text())
    assert set(CONFIDENCE_RANK) == set(schema["properties"]["confidence"]["enum"])


def test_finding_paths_never_reach_the_filesystem(truth, monkeypatch):
    seen = []
    real = os.path.realpath
    monkeypatch.setattr(os.path, "realpath", lambda p, **kw: (seen.append(p), real(p, **kw))[1])

    match([finding(file="/elsewhere/routes/search.ts")], truth, TARGET_ROOT)

    assert "/elsewhere" not in " ".join(map(str, seen))


@pytest.mark.parametrize(
    "file",
    [
        pytest.param("/target/a\x00b/search.ts", id="null byte under the root"),
        pytest.param("/elsewhere/a\x00b.ts", id="null byte outside the root"),
        pytest.param("//server/share/routes/search.ts", id="UNC path"),
        pytest.param("\\\\server\\share\\routes\\search.ts", id="UNC path with backslashes"),
    ],
)
def test_hostile_finding_path_is_an_ordinary_false_positive(truth, file):
    found = finding(file=file)

    result = match([found], truth, TARGET_ROOT)

    assert [fp.finding for fp in result.false_positives] == [found]


def test_whole_file_range_does_not_match(truth):
    found = finding(line=1, end_line=99999)

    result = match([found], truth, TARGET_ROOT)

    assert result.matches == []
    assert result.duplicates == []
    assert [fp.finding for fp in result.false_positives] == [found]
    assert ids(result.false_negatives) == ["SQLI-01", "IDOR-01"]


def test_whole_file_ranges_cannot_claim_every_entry_in_a_file():
    truth = truth_with_second_sqli_entry()
    found = [finding(line=1, end_line=99999, id=id) for id in ("SEC-0001", "SEC-0002")]

    result = match(found, truth, TARGET_ROOT)

    assert result.matches == []
    assert result.duplicates == []
    assert [fp.finding for fp in result.false_positives] == found
    assert ids(result.false_negatives) == ["SQLI-01", "SQLI-02"]


@pytest.mark.parametrize(
    "line, end_line",
    [
        pytest.param(38, 50, id="multi-line finding around the location"),
        pytest.param(35, 53, id="as wide as the location plus the tolerance on each side"),
    ],
)
def test_finding_no_wider_than_location_plus_tolerance_matches(truth, line, end_line):
    result = match([finding(line=line, end_line=end_line)], truth, TARGET_ROOT)

    assert ids(m.entry for m in result.matches) == ["SQLI-01"]


def test_finding_one_line_wider_than_location_plus_tolerance_is_a_false_positive(truth):
    found = finding(line=35, end_line=54)

    result = match([found], truth, TARGET_ROOT)

    assert result.matches == []
    assert result.duplicates == []
    assert [fp.finding for fp in result.false_positives] == [found]
    assert ids(result.false_negatives) == ["SQLI-01", "IDOR-01"]


@pytest.mark.parametrize(
    "line, end_line, expected",
    [
        pytest.param(8, 30, ["SQLI-01"], id="too wide for the small location, fits the large one"),
        pytest.param(5, 40, [], id="too wide for both locations"),
    ],
)
def test_span_limit_is_judged_per_location(line, end_line, expected):
    truth = truth_with_small_and_large_sqli_locations()

    result = match([finding(line=line, end_line=end_line)], truth, TARGET_ROOT)

    assert ids(m.entry for m in result.matches) == expected
