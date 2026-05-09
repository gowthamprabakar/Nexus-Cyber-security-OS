"""Tests for Cloud Posture schemas — OCSF v1.3 Compliance Finding typing layer."""

from dataclasses import asdict
from datetime import UTC, datetime

import pytest
from cloud_posture.schemas import (
    AffectedResource,
    CloudPostureFinding,
    FindingsReport,
    Severity,
    build_finding,
    severity_from_id,
    severity_to_id,
)
from shared.fabric.envelope import NexusEnvelope, unwrap_ocsf


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="01HZX7B0K3M5N9P2Q4R6S8T0V0",
        tenant_id="cust_test",
        agent_id="cloud-posture",
        nlah_version="0.1.0",
        model_pin="claude-sonnet-4-5",
        charter_invocation_id="01HZX7B0K3M5N9P2Q4R6S8T0V1",
    )


def _resource() -> AffectedResource:
    return AffectedResource(
        cloud="aws",
        account_id="111122223333",
        region="us-east-1",
        resource_type="aws_s3_bucket",
        resource_id="acme",
        arn="arn:aws:s3:::acme",
    )


def test_severity_enum() -> None:
    assert Severity.CRITICAL.value == "critical"
    assert Severity("high") == Severity.HIGH


@pytest.mark.parametrize(
    ("severity", "expected_id"),
    [
        (Severity.INFO, 1),
        (Severity.LOW, 2),
        (Severity.MEDIUM, 3),
        (Severity.HIGH, 4),
        (Severity.CRITICAL, 5),
    ],
)
def test_severity_to_id_mapping(severity: Severity, expected_id: int) -> None:
    assert severity_to_id(severity) == expected_id
    assert severity_from_id(expected_id) == severity


def test_severity_from_id_collapses_fatal_to_critical() -> None:
    """OCSF severity_id 6 (Fatal) collapses to our `critical`."""
    assert severity_from_id(6) == Severity.CRITICAL


def test_severity_from_id_unknown_raises() -> None:
    with pytest.raises(ValueError, match="unknown OCSF severity_id"):
        severity_from_id(99)


def test_affected_resource_to_ocsf_shape() -> None:
    r = _resource()
    o = r.to_ocsf()
    assert o["type"] == "aws_s3_bucket"
    assert o["uid"] == "arn:aws:s3:::acme"
    assert o["region"] == "us-east-1"
    assert o["owner"]["account_uid"] == "111122223333"


def test_build_finding_returns_compliance_finding_class() -> None:
    f = build_finding(
        finding_id="CSPM-AWS-S3-001-bucket-public-acme",
        rule_id="CSPM-AWS-S3-001",
        severity=Severity.HIGH,
        title="S3 bucket has public ACL",
        description="Bucket 'acme' allows public list/read",
        affected=[_resource()],
        detected_at=datetime.now(UTC),
        envelope=_envelope(),
    )
    payload = f.to_dict()
    assert payload["category_uid"] == 2  # Findings
    assert payload["class_uid"] == 2003  # Compliance Finding
    assert payload["activity_id"] == 1  # Create
    assert payload["type_uid"] == 200301
    assert payload["severity_id"] == 4
    assert payload["metadata"]["version"] == "1.3.0"


def test_build_finding_attaches_envelope_and_round_trips() -> None:
    env = _envelope()
    f = build_finding(
        finding_id="CSPM-AWS-S3-001-bucket-public-acme",
        rule_id="CSPM-AWS-S3-001",
        severity=Severity.HIGH,
        title="t",
        description="d",
        affected=[_resource()],
        detected_at=datetime.now(UTC),
        envelope=env,
    )
    event, recovered = unwrap_ocsf(f.to_dict())
    assert recovered == env
    assert event["class_uid"] == 2003


def test_cloud_posture_finding_typed_accessors() -> None:
    f = build_finding(
        finding_id="CSPM-AWS-IAM-002-alice",
        rule_id="CSPM-AWS-IAM-002",
        severity=Severity.CRITICAL,
        title="Admin policy",
        description="User has Action=* on Resource=*",
        affected=[_resource()],
        detected_at=datetime.now(UTC),
        envelope=_envelope(),
    )
    assert f.severity == Severity.CRITICAL
    assert f.finding_id == "CSPM-AWS-IAM-002-alice"
    assert f.rule_id == "CSPM-AWS-IAM-002"
    assert f.title == "Admin policy"
    assert f.envelope.tenant_id == "cust_test"
    assert len(f.resources) == 1


def test_build_finding_rejects_bad_finding_id() -> None:
    with pytest.raises(ValueError, match="finding_id must match"):
        build_finding(
            finding_id="not_following_format",
            rule_id="CSPM-AWS-S3-001",
            severity=Severity.HIGH,
            title="t",
            description="d",
            affected=[_resource()],
            detected_at=datetime.now(UTC),
            envelope=_envelope(),
        )


def test_build_finding_rejects_empty_affected() -> None:
    with pytest.raises(ValueError, match="affected"):
        build_finding(
            finding_id="CSPM-AWS-S3-001-x",
            rule_id="CSPM-AWS-S3-001",
            severity=Severity.HIGH,
            title="t",
            description="d",
            affected=[],
            detected_at=datetime.now(UTC),
            envelope=_envelope(),
        )


def test_cloud_posture_finding_rejects_wrong_class_uid() -> None:
    bad_payload = {
        "class_uid": 2004,  # Detection Finding, not Compliance Finding
        "finding_info": {"uid": "CSPM-AWS-S3-001-x"},
        "nexus_envelope": asdict(_envelope()),
    }
    with pytest.raises(ValueError, match="class_uid"):
        CloudPostureFinding(bad_payload)


def test_cloud_posture_finding_rejects_missing_envelope() -> None:
    """A payload without nexus_envelope must be rejected at construction time."""
    payload = {
        "category_uid": 2,
        "class_uid": 2003,
        "severity_id": 4,
        "finding_info": {"uid": "CSPM-AWS-S3-001-x"},
    }
    with pytest.raises(ValueError, match="nexus_envelope"):
        CloudPostureFinding(payload)


def test_findings_report_aggregates_by_severity() -> None:
    env = _envelope()
    f1 = build_finding(
        finding_id="CSPM-AWS-S3-001-x",
        rule_id="CSPM-AWS-S3-001",
        severity=Severity.HIGH,
        title="t",
        description="d",
        affected=[_resource()],
        detected_at=datetime.now(UTC),
        envelope=env,
    )
    f2 = build_finding(
        finding_id="CSPM-AWS-IAM-002-y",
        rule_id="CSPM-AWS-IAM-002",
        severity=Severity.CRITICAL,
        title="t",
        description="d",
        affected=[_resource()],
        detected_at=datetime.now(UTC),
        envelope=env,
    )
    report = FindingsReport(
        agent="cloud_posture",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="r1",
        scan_started_at=datetime.now(UTC),
        scan_completed_at=datetime.now(UTC),
    )
    report.add_finding(f1)
    report.add_finding(f2)

    assert report.total == 2
    assert report.count_by_severity() == {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 1,
        "critical": 1,
    }
