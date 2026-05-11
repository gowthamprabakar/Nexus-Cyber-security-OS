"""Tests for `identity.summarizer.render_summary`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from identity.schemas import (
    AffectedPrincipal,
    FindingsReport,
    FindingType,
    IdentityFinding,
    Severity,
    build_finding,
)
from identity.summarizer import render_summary
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 5, 11, tzinfo=UTC)
ALICE = "arn:aws:iam::123456789012:user/alice"
BOB = "arn:aws:iam::123456789012:user/bob"
CHARLIE_ROLE = "arn:aws:iam::123456789012:role/Charlie"


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="identity@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic-v0.1",
        charter_invocation_id="invocation_001",
    )


def _principal(arn: str, name: str, ptype: str = "User") -> AffectedPrincipal:
    return AffectedPrincipal(
        principal_type=ptype,
        principal_name=name,
        arn=arn,
        account_id="123456789012",
    )


def _empty_report() -> FindingsReport:
    return FindingsReport(
        agent="identity",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_xyz",
        scan_started_at=NOW,
        scan_completed_at=NOW,
        findings=[],
    )


def _make_finding(
    *,
    finding_id: str,
    finding_type: FindingType,
    severity: Severity,
    principal_arn: str = ALICE,
    principal_name: str = "alice",
    title: str = "Test finding",
) -> IdentityFinding:
    return build_finding(
        finding_id=finding_id,
        finding_type=finding_type,
        severity=severity,
        title=title,
        description="test",
        affected_principals=[_principal(principal_arn, principal_name)],
        evidence={"k": "v"},
        detected_at=NOW,
        envelope=_envelope(),
    )


def _report_with(findings: list[IdentityFinding]) -> FindingsReport:
    report = _empty_report()
    for f in findings:
        report.add_finding(f)
    return report


# ---------------------------- empty path ---------------------------------


def test_empty_report_returns_clean_summary() -> None:
    out = render_summary(_empty_report())
    assert "# Identity Scan" in out
    assert "Total findings: **0**" in out
    assert "No identity risk detected" in out


# ---------------------------- per-finding-type cases --------------------


def test_overprivilege_finding_appears_in_high_risk_section() -> None:
    finding = _make_finding(
        finding_id="IDENT-OVERPRIV-ALICE-001-admin_grants",
        finding_type=FindingType.OVERPRIVILEGE,
        severity=Severity.HIGH,
    )
    out = render_summary(_report_with([finding]))
    assert "High-risk principals" in out
    assert ALICE in out


def test_dormant_only_does_not_create_high_risk_section() -> None:
    finding = _make_finding(
        finding_id="IDENT-DORMANT-ALICE-001-user_inactive",
        finding_type=FindingType.DORMANT,
        severity=Severity.MEDIUM,
    )
    out = render_summary(_report_with([finding]))
    assert "High-risk principals" not in out
    # but the finding itself must still appear
    assert "IDENT-DORMANT-ALICE-001-user_inactive" in out


def test_external_access_finding_listed_in_high_risk() -> None:
    finding = _make_finding(
        finding_id="IDENT-EXTERNAL-PUBLIC-001-bucket",
        finding_type=FindingType.EXTERNAL_ACCESS,
        severity=Severity.CRITICAL,
        principal_arn="arn:aws:iam:::*",
        principal_name="*",
    )
    out = render_summary(_report_with([finding]))
    assert "High-risk principals" in out
    assert "arn:aws:iam:::*" in out


def test_mfa_gap_finding_listed_in_high_risk() -> None:
    finding = _make_finding(
        finding_id="IDENT-MFA-ALICE-001-admin_no_mfa",
        finding_type=FindingType.MFA_GAP,
        severity=Severity.CRITICAL,
    )
    out = render_summary(_report_with([finding]))
    assert "High-risk principals" in out
    assert ALICE in out


# ---------------------------- dedup + ordering --------------------------


def test_high_risk_section_dedupes_principals() -> None:
    overpriv = _make_finding(
        finding_id="IDENT-OVERPRIV-ALICE-001-admin_grants",
        finding_type=FindingType.OVERPRIVILEGE,
        severity=Severity.HIGH,
    )
    mfa = _make_finding(
        finding_id="IDENT-MFA-ALICE-001-admin_no_mfa",
        finding_type=FindingType.MFA_GAP,
        severity=Severity.CRITICAL,
    )
    out = render_summary(_report_with([overpriv, mfa]))
    # The high-risk section header says "(1)" — one unique principal.
    assert "High-risk principals (1)" in out
    # And the ARN appears only once in the high-risk bullet list.
    high_risk_block = out.split("High-risk principals")[1].split("## Findings")[0]
    assert high_risk_block.count(f"`{ALICE}`") == 1


def test_severity_order_is_critical_first() -> None:
    """The per-severity sections must list Critical above High above Medium."""
    findings = [
        _make_finding(
            finding_id="IDENT-DORMANT-BOB-001-user_inactive",
            finding_type=FindingType.DORMANT,
            severity=Severity.MEDIUM,
            principal_arn=BOB,
            principal_name="bob",
        ),
        _make_finding(
            finding_id="IDENT-MFA-ALICE-001-admin_no_mfa",
            finding_type=FindingType.MFA_GAP,
            severity=Severity.CRITICAL,
        ),
        _make_finding(
            finding_id="IDENT-OVERPRIV-CHARLIE-001-admin_grants",
            finding_type=FindingType.OVERPRIVILEGE,
            severity=Severity.HIGH,
            principal_arn=CHARLIE_ROLE,
            principal_name="Charlie",
        ),
    ]
    out = render_summary(_report_with(findings))
    crit_pos = out.index("### Critical")
    high_pos = out.index("### High")
    med_pos = out.index("### Medium")
    assert crit_pos < high_pos < med_pos


# ---------------------------- counts -------------------------------------


def test_finding_type_breakdown_counts_match_findings() -> None:
    findings = [
        _make_finding(
            finding_id="IDENT-OVERPRIV-ALICE-001-admin_grants",
            finding_type=FindingType.OVERPRIVILEGE,
            severity=Severity.HIGH,
        ),
        _make_finding(
            finding_id="IDENT-OVERPRIV-BOB-002-admin_grants",
            finding_type=FindingType.OVERPRIVILEGE,
            severity=Severity.HIGH,
            principal_arn=BOB,
            principal_name="bob",
        ),
        _make_finding(
            finding_id="IDENT-DORMANT-CHARLIE-003-role_inactive",
            finding_type=FindingType.DORMANT,
            severity=Severity.MEDIUM,
            principal_arn=CHARLIE_ROLE,
            principal_name="Charlie",
        ),
    ]
    out = render_summary(_report_with(findings))
    assert "**overprivilege**: 2" in out
    assert "**dormant**: 1" in out
    assert "**mfa_gap**: 0" in out


def test_severity_breakdown_counts_match_findings() -> None:
    findings = [
        _make_finding(
            finding_id="IDENT-MFA-ALICE-001-admin_no_mfa",
            finding_type=FindingType.MFA_GAP,
            severity=Severity.CRITICAL,
        ),
        _make_finding(
            finding_id="IDENT-MFA-BOB-002-admin_no_mfa",
            finding_type=FindingType.MFA_GAP,
            severity=Severity.CRITICAL,
            principal_arn=BOB,
            principal_name="bob",
        ),
    ]
    out = render_summary(_report_with(findings))
    assert "**Critical**: 2" in out
    assert "**High**: 0" in out


def test_metadata_block_emitted() -> None:
    out = render_summary(_empty_report())
    assert "Customer: `cust_test`" in out
    assert "Run ID: `run_xyz`" in out


@pytest.mark.parametrize(
    "finding_type",
    [FindingType.OVERPRIVILEGE, FindingType.EXTERNAL_ACCESS, FindingType.MFA_GAP],
)
def test_each_high_risk_type_triggers_high_risk_section(finding_type: FindingType) -> None:
    """OVERPRIVILEGE / EXTERNAL_ACCESS / MFA_GAP each individually trigger pin."""
    type_token = {
        FindingType.OVERPRIVILEGE: "OVERPRIV",
        FindingType.EXTERNAL_ACCESS: "EXTERNAL",
        FindingType.MFA_GAP: "MFA",
    }[finding_type]
    f = _make_finding(
        finding_id=f"IDENT-{type_token}-ALICE-001-evidence",
        finding_type=finding_type,
        severity=Severity.HIGH,
    )
    out = render_summary(_report_with([f]))
    assert "High-risk principals" in out
