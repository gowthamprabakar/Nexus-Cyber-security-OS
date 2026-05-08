"""Tests for Cloud Posture Pydantic schemas."""

from datetime import UTC, datetime

import pytest
from cloud_posture.schemas import (
    AffectedResource,
    Finding,
    FindingsReport,
    Severity,
)
from pydantic import ValidationError


def test_severity_enum() -> None:
    assert Severity.CRITICAL.value == "critical"
    assert Severity("high") == Severity.HIGH


def test_minimum_finding() -> None:
    finding = Finding(
        finding_id="CSPM-AWS-S3-001-bucket-public-acme",
        rule_id="CSPM-AWS-S3-001",
        severity=Severity.HIGH,
        title="S3 bucket has public ACL",
        description="Bucket 'acme' allows public list/read",
        affected=[
            AffectedResource(
                cloud="aws",
                account_id="111122223333",
                region="us-east-1",
                resource_type="aws_s3_bucket",
                resource_id="acme",
                arn="arn:aws:s3:::acme",
            )
        ],
        evidence={"acl": "public-read"},
        detected_at=datetime.now(UTC),
    )
    assert finding.severity == Severity.HIGH
    assert finding.affected[0].cloud == "aws"


def test_finding_id_format_enforced() -> None:
    """finding_id must follow CSPM-<CLOUD>-<SVC>-<NNN>-<CONTEXT> pattern."""
    with pytest.raises(ValidationError):
        Finding(
            finding_id="not_following_format",
            rule_id="CSPM-AWS-S3-001",
            severity=Severity.HIGH,
            title="x",
            description="x",
            affected=[
                AffectedResource(
                    cloud="aws",
                    account_id="1",
                    region="us-east-1",
                    resource_type="t",
                    resource_id="r",
                    arn="arn:x",
                )
            ],
            evidence={},
            detected_at=datetime.now(UTC),
        )


def test_findings_report_aggregates() -> None:
    finding = Finding(
        finding_id="CSPM-AWS-S3-001-x",
        rule_id="CSPM-AWS-S3-001",
        severity=Severity.HIGH,
        title="x",
        description="x",
        affected=[
            AffectedResource(
                cloud="aws",
                account_id="1",
                region="us-east-1",
                resource_type="t",
                resource_id="r",
                arn="arn:x",
            )
        ],
        evidence={},
        detected_at=datetime.now(UTC),
    )
    report = FindingsReport(
        agent="cloud_posture",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="r1",
        scan_started_at=datetime.now(UTC),
        scan_completed_at=datetime.now(UTC),
        findings=[finding],
    )
    assert report.count_by_severity() == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    assert report.total == 1
