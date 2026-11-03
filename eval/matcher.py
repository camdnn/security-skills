"""Pair a trial's findings one-to-one with a target's truth entries (TICKET-001 §7.4)."""

from __future__ import annotations

import json
import os
import posixpath
import sys
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any

import yaml

Finding = dict[str, Any]
TruthEntry = dict[str, Any]
MustNotFindRule = dict[str, str]

CWE_FAMILIES_PATH = Path(__file__).with_name("cwe_families.json")
CONFIG_PATH = Path(__file__).with_name("config.yaml")
DEFAULT_TOLERANCE = 5
CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}
CASE_INSENSITIVE_SYSTEM = sys.platform in ("darwin", "win32")


@dataclass(frozen=True)
class Match:
    """A finding paired one-to-one with a truth entry."""

    finding: Finding
    entry: TruthEntry


@dataclass(frozen=True)
class Duplicate:
    """A finding that would have matched ``entry``, had another finding not matched it first."""

    finding: Finding
    entry: TruthEntry


@dataclass(frozen=True)
class FalsePositive:
    """A finding that counts against precision; ``must_not_find_rule`` is set if it hit one."""

    finding: Finding
    must_not_find_rule: MustNotFindRule | None = None


@dataclass(frozen=True)
class MatchResult:
    """Every finding and truth entry of a trial, each classified exactly once."""

    matches: list[Match]
    duplicates: list[Duplicate]
    false_positives: list[FalsePositive]
    false_negatives: list[TruthEntry]


def load_tolerance(config_path: Path | str = CONFIG_PATH) -> int:
    """Return ``line_tolerance`` from the checker config, or the default if unset."""
    path = Path(config_path)
    config = yaml.safe_load(path.read_text()) if path.exists() else None
    tolerance = (config or {}).get("line_tolerance")
    return DEFAULT_TOLERANCE if tolerance is None else tolerance


def match(
    findings: list[Finding],
    ground_truth: dict[str, Any],
    target_root: str,
    *,
    tolerance: int | None = None,
    case_insensitive: bool = CASE_INSENSITIVE_SYSTEM,
) -> MatchResult:
    """Classify every finding and truth entry of one trial on one target.

    ``tolerance`` defaults to the configured one. Raises ``ValueError`` if ground
    truth names a CWE or family outside the registry, since such an entry or rule
    could never fire and would silently skew every score. A finding with an
    unregistered CWE is merely unmatchable, so it is a false positive.
    """
    registry = json.loads(CWE_FAMILIES_PATH.read_text())
    cwe_to_family = registry["cwe_to_family"]
    entries = ground_truth["truth"]
    must_not_find = ground_truth.get("must_not_find", [])
    _check_ground_truth_families(entries, must_not_find, registry)
    if tolerance is None:
        tolerance = load_tolerance()

    def normalize(path: str) -> str:
        return _normalize_path(path, target_root, case_insensitive)

    files = [normalize(finding["file"]) for finding in findings]
    families = [cwe_to_family.get(finding["cwe"]) for finding in findings]
    entry_families = [cwe_to_family[entry["cwe"]] for entry in entries]
    entry_locations = [
        [(normalize(loc["file"]), loc["start_line"], loc["end_line"]) for loc in entry["locations"]]
        for entry in entries
    ]
    rules = {
        (normalize(rule["file"]), rule["cwe_family"]): rule
        for rule in must_not_find
    }

    # A must-not-find hit is a false positive whatever else it is near, so it never competes.
    hit_rules = {
        f: rules[file, family]
        for f, (file, family) in enumerate(zip(files, families))
        if (file, family) in rules
    }

    # Closest line first, then higher confidence; list order keeps the result deterministic.
    candidates = sorted(
        (gap, -CONFIDENCE_RANK[finding["confidence"]], f, e)
        for f, finding in enumerate(findings)
        if f not in hit_rules
        for e in range(len(entries))
        if families[f] == entry_families[e]
        and (gap := _line_gap(finding, files[f], entry_locations[e], tolerance)) is not None
    )

    assigned: dict[int, int] = {}
    closest_entry: dict[int, int] = {}
    for _, _, f, e in candidates:
        closest_entry.setdefault(f, e)
        if f not in assigned and e not in assigned.values():
            assigned[f] = e

    # Greedy leaves no candidate pair with both sides free, so a finding with a
    # candidate that is still unassigned lost out to another finding: a duplicate.
    matches = [Match(findings[f], entries[e]) for f, e in sorted(assigned.items())]
    duplicates = [
        Duplicate(finding, entries[closest_entry[f]])
        for f, finding in enumerate(findings)
        if f in closest_entry and f not in assigned
    ]
    false_positives = [
        FalsePositive(finding, hit_rules.get(f))
        for f, finding in enumerate(findings)
        if f not in closest_entry
    ]
    false_negatives = [entry for e, entry in enumerate(entries) if e not in assigned.values()]
    return MatchResult(matches, duplicates, false_positives, false_negatives)


def _check_ground_truth_families(
    entries: list[TruthEntry], must_not_find: list[MustNotFindRule], registry: dict[str, Any]
) -> None:
    """Raise ``ValueError`` if ground truth names a CWE or family outside the registry."""
    for entry in entries:
        if entry["cwe"] not in registry["cwe_to_family"]:
            raise ValueError(f"truth entry {entry['id']}: {entry['cwe']} has no CWE family")
    for rule in must_not_find:
        if rule["cwe_family"] not in registry["families"]:
            raise ValueError(f"must-not-find rule on {rule['file']}: unknown family {rule['cwe_family']}")


def _line_gap(
    finding: Finding, file: str, locations: list[tuple[str, int, int]], tolerance: int
) -> int | None:
    """Lines between the finding and its nearest location in ``file``; None if out of tolerance.

    Anything overlapping a location has gap 0: it is all equally on target, so
    confidence, not position within the location, separates such findings.
    """
    first = finding["line"]
    last = finding.get("end_line") or first
    gaps = [
        max(0, start - last, first - end)
        for location_file, start, end in locations
        if location_file == file
    ]
    gap = min(gaps, default=None)
    return gap if gap is not None and gap <= tolerance else None


def _normalize_path(path: str, target_root: str, case_insensitive: bool) -> str:
    """Return ``path`` relative to the target root, with forward slashes."""
    path = posixpath.normpath(path.replace("\\", "/"))
    if posixpath.isabs(path) or os.path.isabs(path):
        path = _relative_to_root(path, target_root, case_insensitive)
    return path.lower() if case_insensitive else path


def _relative_to_root(path: str, target_root: str, case_insensitive: bool) -> str:
    """Strip the target root from an absolute ``path``, however the root is spelled.

    Agents may report through a different alias of the temp copy than the runner
    holds (macOS /tmp is a symlink to /private/tmp), so ancestors are compared by
    real path. What lies below the root stays textual, like truth paths, so a symlink
    inside the target can't change the result. A path outside the root stays absolute.
    """

    def real(candidate: PurePath | str) -> str:
        resolved = os.path.realpath(candidate)
        return resolved.lower() if case_insensitive else resolved

    root = real(target_root)
    absolute = PurePath(path)
    for ancestor in reversed(absolute.parents):
        if real(ancestor) == root:
            return absolute.relative_to(ancestor).as_posix()
    return path
