"""Tests for `multi_cloud_posture.summarizer` — markdown renderer with per-cloud + CRITICAL pin."""

from __future__ import annotations

from datetime import UTC, datetime

from multi_cloud_posture.normalizers.azure import normalize_azure
from multi_cloud_posture.normalizers.gcp import normalize_gcp
from multi_cloud_posture.schemas import FindingsReport
from multi_cloud_posture.summarizer import render_summary
from multi_cloud_posture.tools.azure_activity import AzureActivityRecord
from multi_cloud_posture.tools.azure_defender import AzureDefenderFinding
from multi_cloud_posture.tools.gcp_iam import GcpIamFinding
from multi_cloud_posture.tools.gcp_scc import GcpSccFinding
from shared.fabric.envelope import NexusEnvelope

NOW = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="multi_cloud_posture@0.1.0",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_001",
    )


def _empty_report() -> FindingsReport:
    return FindingsReport(
        agent="multi_cloud_posture",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="run_001",
        scan_started_at=datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 13, 12, 5, 0, tzinfo=UTC),
    )


def _build_report(
    *,
    defender: list[AzureDefenderFinding] | None = None,
    activity: list[AzureActivityRecord] | None = None,
    scc: list[GcpSccFinding] | None = None,
    iam: list[GcpIamFinding] | None = None,
) -> FindingsReport:
    rpt = _empty_report()
    env = _envelope()
    if defender or activity:
        azf = normalize_azure(
            defender=defender or [],
            activity=activity or [],
            envelope=env,
            scan_time=NOW,
        )
        for f in azf:
            rpt.add_finding(f)
    if scc or iam:
        gpf = normalize_gcp(
            scc=scc or [],
            iam=iam or [],
            envelope=env,
            scan_time=NOW,
        )
        for f in gpf:
            rpt.add_finding(f)
    return rpt


# Fixtures


def _defender(severity: str = "High") -> AzureDefenderFinding:
    return AzureDefenderFinding(
        kind="assessment",
        record_id="/subscriptions/aaa-bbb/providers/Microsoft.Security/assessments/asmt-001",
        display_name="Restrict storage account public access",
        severity=severity,
        status="Unhealthy",
        description="x",
        resource_id="/subscriptions/aaa-bbb/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
        subscription_id="aaa-bbb",
        assessment_type="BuiltIn",
        detected_at=NOW,
    )


def _activity(level: str = "Critical") -> AzureActivityRecord:
    return AzureActivityRecord(
        record_id="/subscriptions/aaa-bbb/providers/microsoft.insights/eventtypes/management/values/evt-001",
        operation_name="Microsoft.Authorization/roleAssignments/write",
        operation_class="iam",
        category="Administrative",
        level=level,
        status="Succeeded",
        caller="user@example.com",
        resource_id="/subscriptions/aaa-bbb/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
        subscription_id="aaa-bbb",
        resource_group="rg1",
        detected_at=NOW,
    )


def _scc(severity: str = "CRITICAL", category: str = "PUBLIC_BUCKET") -> GcpSccFinding:
    return GcpSccFinding(
        finding_name="organizations/123/sources/456/findings/finding-001",
        parent="organizations/123/sources/456",
        resource_name="//storage.googleapis.com/projects/proj-xyz/buckets/public-bucket",
        category=category,
        state="ACTIVE",
        severity=severity,
        description="x",
        project_id="proj-xyz",
        detected_at=NOW,
    )


def _iam(severity: str = "HIGH") -> GcpIamFinding:
    return GcpIamFinding(
        asset_name="//cloudresourcemanager.googleapis.com/projects/proj-xyz",
        asset_type="cloudresourcemanager.googleapis.com/Project",
        project_id="proj-xyz",
        role="roles/owner",
        member="user:alice@example.com",
        severity=severity,
        reason="x",
        detected_at=NOW,
    )


# ---------------------------- empty report -------------------------------


def test_empty_report_renders_no_findings_message() -> None:
    md = render_summary(_empty_report())
    assert "# Multi-Cloud Posture Scan" in md
    assert "No multi-cloud posture findings" in md
    # Severity/per-cloud breakdowns skipped when empty.
    assert "Severity breakdown" not in md
    assert "Per-cloud breakdown" not in md


def test_header_carries_metadata() -> None:
    md = render_summary(_build_report(defender=[_defender()]))
    assert "cust_test" in md
    assert "run_001" in md
    assert "Scan window:" in md
    assert "Total findings: **1**" in md


# ---------------------------- per-cloud breakdown ------------------------


def test_per_cloud_pin_present_above_per_severity() -> None:
    md = render_summary(_build_report(defender=[_defender()], scc=[_scc()]))
    pcb_idx = md.find("## Per-cloud breakdown")
    findings_idx = md.find("## Findings")
    assert pcb_idx > 0
    assert findings_idx > pcb_idx


def test_per_cloud_breakdown_counts_correct() -> None:
    md = render_summary(
        _build_report(
            defender=[_defender(), _defender()],
            activity=[_activity()],
            scc=[_scc()],
            iam=[_iam(), _iam(), _iam()],
        )
    )
    # Azure total = 2 defender + 1 activity = 3
    assert "**Azure**: 3" in md
    # GCP total = 1 SCC + 3 IAM = 4
    assert "**GCP**:   4" in md
    # Per-source counts in the breakdown line.
    assert "Defender: 2" in md
    assert "Activity: 1" in md
    assert "SCC: 1" in md
    assert "IAM: 3" in md


def test_per_cloud_only_azure() -> None:
    md = render_summary(_build_report(defender=[_defender()]))
    assert "**Azure**: 1" in md
    assert "**GCP**:   0" in md


def test_per_cloud_only_gcp() -> None:
    md = render_summary(_build_report(scc=[_scc()]))
    assert "**GCP**:   1" in md
    assert "**Azure**: 0" in md


# ---------------------------- source-type breakdown ----------------------


def test_source_type_breakdown_lists_all_four() -> None:
    md = render_summary(_build_report(defender=[_defender()]))
    assert "**cspm_azure_defender**: 1" in md
    assert "**cspm_azure_activity**: 0" in md
    assert "**cspm_gcp_scc**: 0" in md
    assert "**cspm_gcp_iam**: 0" in md


# ---------------------------- CRITICAL pin -------------------------------


def test_critical_pin_present_when_critical_exists() -> None:
    md = render_summary(
        _build_report(
            defender=[_defender(severity="Critical")],
            scc=[_scc(severity="CRITICAL")],
        )
    )
    pin_idx = md.find("## Critical findings")
    findings_idx = md.find("## Findings")
    assert pin_idx > 0
    assert findings_idx > pin_idx
    # Includes both CRITICAL findings.
    assert "Cloud: azure" in md
    assert "Cloud: gcp" in md


def test_no_critical_pin_when_no_criticals() -> None:
    md = render_summary(_build_report(defender=[_defender(severity="Medium")]))
    assert "## Critical findings" not in md


# ---------------------------- per-severity sections ----------------------


def test_per_severity_sections_emitted_for_present_buckets() -> None:
    md = render_summary(
        _build_report(
            defender=[
                _defender(severity="Critical"),
                _defender(severity="Medium"),
            ],
        )
    )
    assert "### Critical (1)" in md
    assert "### Medium (1)" in md
    # High not present.
    assert "### High (" not in md


def test_severity_sections_ordered_critical_first() -> None:
    md = render_summary(
        _build_report(defender=[_defender(severity="Critical"), _defender(severity="Medium")])
    )
    crit_idx = md.find("### Critical")
    med_idx = md.find("### Medium")
    assert crit_idx > 0 and med_idx > crit_idx


# ---------------------------- finding rendering --------------------------


def test_finding_lines_include_cloud_and_source() -> None:
    md = render_summary(_build_report(scc=[_scc()]))
    # `Cloud: gcp; Source: cspm_gcp_scc`
    assert "Cloud: gcp" in md
    assert "Source: cspm_gcp_scc" in md


def test_finding_lines_truncate_long_resource_ids() -> None:
    """The summarizer trims long resource IDs to the last two segments."""
    md = render_summary(_build_report(defender=[_defender()]))
    # The Azure resource_id is long; summarizer shortens to `.../storageAccounts/sa1`.
    assert ".../storageAccounts/sa1" in md
