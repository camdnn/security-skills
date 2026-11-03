"""Tests for the authoritative CWE-family and owning-check registry."""

import json
import re
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
REGISTRY = REPO / "eval/cwe_families.json"
EXPECTED_OWNERS = {
    "access-control": "access-control-check",
    "auth-session": "auth-session-check",
    "crypto": "crypto-check",
    "dependency": "dependency-check",
    "error-logging": "error-logging-check",
    "file-handling": "file-handling-check",
    "injection": "injection-check",
    "misconfiguration": "misconfiguration-check",
    "secrets": "secrets-check",
    "xss": "xss-check",
}


def load_registry() -> dict:
    return json.loads(REGISTRY.read_text())


def test_registry_has_only_the_two_authoritative_maps():
    registry = load_registry()
    assert set(registry) == {"cwe_to_family", "families"}
    assert all(isinstance(value, dict) for value in registry.values())


def test_every_mapped_cwe_uses_a_known_family():
    registry = load_registry()
    assert registry["cwe_to_family"]
    assert all(
        re.fullmatch(r"CWE-[1-9][0-9]*", cwe)
        and family in registry["families"]
        for cwe, family in registry["cwe_to_family"].items()
    )


def test_each_cwe_family_has_its_one_locked_owning_check():
    assert load_registry()["families"] == EXPECTED_OWNERS


def test_related_cwes_share_their_locked_family():
    cwe_to_family = load_registry()["cwe_to_family"]
    assert {cwe_to_family[cwe] for cwe in ("CWE-78", "CWE-89", "CWE-94")} == {"injection"}
    assert {cwe_to_family[cwe] for cwe in ("CWE-22", "CWE-434", "CWE-502")} == {"file-handling"}
    assert cwe_to_family["CWE-918"] == "access-control"
