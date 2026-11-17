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


def test_v1_defers_module_contract_and_coverage_staleness():
    skill = SKILL.read_text(encoding="utf-8")

    assert "Module contracts" in skill
    assert "only after a later context format adds module files" in skill
    assert "do not infer them from the v1 index table" in skill
