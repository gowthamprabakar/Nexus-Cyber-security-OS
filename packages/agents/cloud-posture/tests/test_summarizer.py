"""Tests for the markdown summarizer (consumes OCSF-wrapped FindingsReport)."""

from datetime import UTC, datetime

from cloud_posture.schemas import (
    AffectedResource,
    CloudPostureFinding,
    FindingsReport,
    Severity,
    build_finding,
)
from cloud_posture.summarizer import render_summary
from shared.fabric.envelope import NexusEnvelope


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="01HZX7B0K3M5N9P2Q4R6S8T0V0",
        tenant_id="cust_test",
        agent_id="cloud-posture",
        nlah_version="0.1.0",
        model_pin="claude-sonnet-4-5",
        charter_invocation_id="01HZX7B0K3M5N9P2Q4R6S8T0V1",
    )


def _resource(arn: str = "arn:aws:s3:::alpha") -> AffectedResource:
    return AffectedResource(
        cloud="aws",
        account_id="111122223333",
        region="us-east-1",
        resource_type="aws_s3_bucket",
        resource_id=arn.split(":")[-1],
        arn=arn,
    )


def _finding(
    severity: Severity, finding_id: str, *, arn: str = "arn:aws:s3:::alpha"
) -> CloudPostureFinding:
    return build_finding(
        finding_id=finding_id,
        rule_id="CSPM-AWS-S3-001",
        severity=severity,
        title="example",
        description="example finding",
        affected=[_resource(arn)],
        detected_at=datetime(2026, 5, 8, 10, 1, tzinfo=UTC),
        envelope=_envelope(),
    )


def _empty_report() -> FindingsReport:
    return FindingsReport(
        agent="cloud_posture",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="r1",
        scan_started_at=datetime(2026, 5, 8, 10, 0, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 8, 10, 5, tzinfo=UTC),
    )


def _report_with(findings: list[CloudPostureFinding]) -> FindingsReport:
    r = _empty_report()
    for f in findings:
        r.add_finding(f)
    return r


def test_summary_empty_report() -> None:
    out = render_summary(_empty_report())
    assert "# Cloud Posture Scan" in out
    assert "No findings" in out
    assert "cust_test" in out
    assert "r1" in out


def test_summary_groups_by_severity() -> None:
    findings = [
        _finding(Severity.CRITICAL, "CSPM-AWS-S3-001-a"),
        _finding(Severity.HIGH, "CSPM-AWS-S3-001-b"),
        _finding(Severity.HIGH, "CSPM-AWS-S3-001-c"),
        _finding(Severity.LOW, "CSPM-AWS-S3-001-d"),
    ]
    out = render_summary(_report_with(findings))
    assert "**Critical**: 1" in out
    assert "**High**: 2" in out
    assert "**Low**: 1" in out
    assert "**Medium**: 0" in out


def test_summary_lists_finding_ids_and_arns() -> None:
    f = _finding(Severity.HIGH, "CSPM-AWS-S3-001-alpha", arn="arn:aws:s3:::alpha")
    out = render_summary(_report_with([f]))
    assert "CSPM-AWS-S3-001-alpha" in out
    assert "arn:aws:s3:::alpha" in out


def test_summary_orders_severity_high_to_low() -> None:
    """The Findings section must list Critical first, then High, Medium, Low, Info."""
    findings = [
        _finding(Severity.LOW, "CSPM-AWS-S3-001-low"),
        _finding(Severity.CRITICAL, "CSPM-AWS-S3-001-crit"),
        _finding(Severity.MEDIUM, "CSPM-AWS-S3-001-med"),
    ]
    out = render_summary(_report_with(findings))
    crit_pos = out.find("CSPM-AWS-S3-001-crit")
    med_pos = out.find("CSPM-AWS-S3-001-med")
    low_pos = out.find("CSPM-AWS-S3-001-low")
    assert 0 < crit_pos < med_pos < low_pos


def test_summary_omits_empty_severity_sections() -> None:
    """A Findings subsection is only rendered when that severity has findings."""
    findings = [_finding(Severity.HIGH, "CSPM-AWS-S3-001-h")]
    out = render_summary(_report_with(findings))
    # The breakdown table still shows "Critical: 0" but the per-severity
    # detail subsection is skipped.
    assert "### High (1)" in out
    assert "### Critical" not in out
    assert "### Low" not in out


def test_summary_includes_total_count() -> None:
    findings = [_finding(Severity.HIGH, f"CSPM-AWS-S3-001-h{i}") for i in range(3)]
    out = render_summary(_report_with(findings))
    assert "Total findings: **3**" in out


def test_summary_includes_multiple_arns_for_one_finding() -> None:
    f = build_finding(
        finding_id="CSPM-AWS-S3-001-multi",
        rule_id="CSPM-AWS-S3-001",
        severity=Severity.HIGH,
        title="multi-bucket finding",
        description="x",
        affected=[
            _resource("arn:aws:s3:::alpha"),
            _resource("arn:aws:s3:::beta"),
        ],
        detected_at=datetime(2026, 5, 8, 10, 1, tzinfo=UTC),
        envelope=_envelope(),
    )
    out = render_summary(_report_with([f]))
    assert "arn:aws:s3:::alpha" in out
    assert "arn:aws:s3:::beta" in out
