"""compliance v0.2 Task 7 — PASS evidence collection tests (WI-C6 positive evidence)."""

from __future__ import annotations

from compliance.attestation import (
    ControlAttestation,
    build_attestation,
    control_can_be_attested,
)

_AT = "2026-06-11T12:00:00+00:00"


def test_can_attest_all_evaluated_and_passing() -> None:
    assert control_can_be_attested(
        ["CSPM-AWS-EC2-001"],
        evaluated_rule_ids={"CSPM-AWS-EC2-001", "CSPM-AWS-S3-001"},
        failing_rule_ids=set(),
    )


def test_cannot_attest_when_a_rule_failed() -> None:
    assert not control_can_be_attested(
        ["CSPM-AWS-EC2-001"],
        evaluated_rule_ids={"CSPM-AWS-EC2-001"},
        failing_rule_ids={"CSPM-AWS-EC2-001"},
    )


def test_cannot_attest_when_a_rule_not_evaluated() -> None:
    # Positive-evidence discipline: a mapped rule that never ran is NOT a pass.
    assert not control_can_be_attested(
        ["CSPM-AWS-EC2-001", "CSPM-AWS-S3-001"],
        evaluated_rule_ids={"CSPM-AWS-EC2-001"},
        failing_rule_ids=set(),
    )


def test_cannot_attest_unwired_control() -> None:
    assert not control_can_be_attested([], evaluated_rule_ids={"x"}, failing_rule_ids=set())


def test_build_attestation_shape() -> None:
    att = build_attestation(
        control_id="5.2",
        framework="cis_aws_v3",
        mapped_rule_ids=["CSPM-AWS-EC2-001", "CSPM-AWS-EC2-001"],
        source_finding_ids=["F-1"],
        attested_at=_AT,
    )
    assert isinstance(att, ControlAttestation)
    assert att.checked_rules == ("CSPM-AWS-EC2-001",)  # deduped + sorted
    assert att.source_finding_ids == ("F-1",) and att.attested_at == _AT


def test_to_evidence_is_positive() -> None:
    ev = build_attestation(
        control_id="5.2",
        framework="cis_aws_v3",
        mapped_rule_ids=["CSPM-AWS-EC2-001"],
        attested_at=_AT,
    ).to_evidence()
    assert ev["kind"] == "compliance_pass"
    assert ev["checked_rules"] == ["CSPM-AWS-EC2-001"]
    assert ev["evidence_payload"]["evaluated_rule_count"] == 1
    assert ev["evidence_payload"]["all_passing"] is True


def test_evidence_feeds_build_pass_finding() -> None:
    # The attestation is a valid (non-empty) positive evidence for build_pass_finding.
    from datetime import UTC, datetime

    from cloud_posture.schemas import AffectedResource
    from compliance.schemas import ComplianceFramework, build_pass_finding
    from shared.fabric.envelope import NexusEnvelope

    ev = build_attestation(
        control_id="1.4",
        framework="cis_aws_v3",
        mapped_rule_ids=["CSPM-AWS-IAM-002"],
        attested_at=_AT,
    ).to_evidence()
    finding = build_pass_finding(
        finding_id="COMPLIANCE-CIS_AWS_V3-1.4-001-pass",
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id="1.4",
        title="t",
        description="d",
        affected=[
            AffectedResource(
                cloud="aws",
                account_id="1",
                region="us-east-1",
                resource_type="account",
                resource_id="1",
                arn="arn:aws:iam::1:root",
            )
        ],
        detected_at=datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC),
        envelope=NexusEnvelope(
            correlation_id="c",
            tenant_id="t",
            agent_id="compliance",
            nlah_version="0.2.0",
            model_pin="deterministic",
            charter_invocation_id="i",
        ),
        attestation=ev,
    )
    assert finding.to_dict()["compliance"]["status"] == "Passed"
