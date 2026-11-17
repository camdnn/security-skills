"""The scan skill consumes the security-context v1 hand-off (issue #88)."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills/security-scan/SKILL.md"


def test_scan_loads_v1_business_rules_and_plan():
    skill = SKILL.read_text(encoding="utf-8")

    assert "SECURITY-CONTEXT.md" in skill
    assert "Business rules" in skill
    assert "BR-n" in skill
    assert "PLAN.md" in skill
    assert "pre-findings" in skill
    assert "recommended scan focus" in skill


def test_pre_findings_are_not_promoted_to_scored_findings():
    skill = SKILL.read_text(encoding="utf-8")

    assert "A pre-finding is a lead" in skill
    assert "not a finding" in skill
    assert "no DREAD score" in skill
    assert "never receives a `SEC-` identifier" in skill


def test_context_findings_cite_the_exact_business_rule_id():
    skill = SKILL.read_text(encoding="utf-8")

    assert "exact cited `BR-n` identifier" in skill
    assert "`context_ref`" in skill
    assert "`BR-1`" in skill


def test_scan_uses_module_contracts_and_staleness():
    """Week 3 (techniques C + E + G): contracts guide tracing, stale modules are flagged, search fills gaps."""

    skill = SKILL.read_text(encoding="utf-8")

    assert "docs/security/modules/" in skill
    assert "](scripts/stale_modules.py)" in skill
    assert "stale-context warnings" in skill
    assert "ASSUMES / GUARANTEES" in skill
    assert "`unverified`" in skill
    assert "Search the code on demand" in skill


def test_fan_out_is_optional_and_sequential_is_the_portable_path():
    """Technique D is a Claude-only option; every agent can run checks one after another (ADR-0004)."""

    skill = SKILL.read_text(encoding="utf-8")

    assert "sequential" in skill
    assert "(module × check)" in skill
    assert "optional and never required" in skill
    assert "untrusted data" in skill
