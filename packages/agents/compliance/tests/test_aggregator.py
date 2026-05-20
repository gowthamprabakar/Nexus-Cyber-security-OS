"""Tests — ``compliance.aggregator`` (Task 8).

Validates the per-control PASS/FAIL roll-up:

- Group by ``compliance.control`` value.
- max-severity across contributors.
- FAIL-only output in v0.1 (PASS controls omitted).
- Evidence carries contributing_finding_ids +
  contributing_source_findings + control metadata.
- Resource union, dedup by arn.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from compliance.aggregator import aggregate_controls
from compliance.schemas import (
    AffectedResource,
    ComplianceFinding,
    ComplianceFramework,
    Severity,
    build_finding,
)
from shared.fabric.envelope import NexusEnvelope


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="00000000-0000-0000-0000-00000000d6d6",
        tenant_id="acme",
        agent_id="compliance",
        nlah_version="d6-v0.1",
        model_pin="deterministic",
        charter_invocation_id="00000000-0000-0000-0000-000000000001",
    )


def _resource(arn: str = "arn:aws:iam::123456789012:user/alice") -> AffectedResource:
    return AffectedResource(
        cloud="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_iam_user",
        resource_id=arn.rsplit("/", 1)[-1],
        arn=arn,
    )


def _finding(
    *,
    control_id: str = "1.10",
    severity: Severity = Severity.HIGH,
    source_agent: str = "cloud_posture",
    source_finding_id: str = "CSPM-AWS-IAM-001-alice",
    source_rule_id: str = "CSPM-AWS-IAM-001",
    arn: str = "arn:aws:iam::123456789012:user/alice",
    sequence: int = 1,
    hash_tag: str = "f3_aabbccdd",
) -> ComplianceFinding:
    control_token = control_id.replace(".", "_")
    return build_finding(
        finding_id=f"COMPLIANCE-CIS_AWS_V3-{control_token}-{sequence:03d}-{hash_tag}",
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id=control_id,
        severity=severity,
        title=f"CIS {control_id} — test contributor",
        description=f"Per-mapping emit for control {control_id}.",
        affected=[_resource(arn)],
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        evidence={
            "source_finding": {
                "agent": source_agent,
                "finding_id": source_finding_id,
                "rule_id": source_rule_id,
            },
            "control": {
                "framework": "cis_aws_v3",
                "control_id": control_id,
                "level": "level_1",
                "required": True,
            },
        },
    )


# ---------------------------------------------------------------------------
# Empty / no-op paths
# ---------------------------------------------------------------------------


def test_empty_input_returns_empty_tuple() -> None:
    assert (
        aggregate_controls(
            [], envelope=_envelope(), aggregated_at=datetime(2026, 5, 21, tzinfo=UTC)
        )
        == ()
    )


def test_only_low_severity_contributors_collapse_to_pass_and_are_omitted() -> None:
    """A control whose only contributors are LOW must be omitted in
    v0.1's FAIL-only output."""
    low = _finding(control_id="2.4.1", severity=Severity.LOW)
    result = aggregate_controls(
        [low],
        envelope=_envelope(),
        aggregated_at=datetime(2026, 5, 21, tzinfo=UTC),
    )
    assert result == ()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_single_high_contributor_emits_one_fail_finding() -> None:
    inp = _finding(control_id="1.10", severity=Severity.HIGH)
    result = aggregate_controls(
        [inp],
        envelope=_envelope(),
        aggregated_at=datetime(2026, 5, 21, tzinfo=UTC),
    )
    assert len(result) == 1
    out = result[0]
    assert out.rule_id == "cis_aws_v3:1.10"
    assert out.severity == Severity.HIGH


def test_aggregated_finding_id_has_aggregated_context_tag() -> None:
    inp = _finding(control_id="1.10", severity=Severity.HIGH)
    result = aggregate_controls(
        [inp],
        envelope=_envelope(),
        aggregated_at=datetime(2026, 5, 21, tzinfo=UTC),
    )
    fid = result[0].finding_id
    assert fid.endswith("-aggregated")
    assert "1_10" in fid
    assert "CIS_AWS_V3" in fid


def test_multiple_contributors_same_control_collapse_to_one_emit() -> None:
    """Two source-findings hitting the same control -> one aggregated emit."""
    a = _finding(
        control_id="2.1.4",
        severity=Severity.HIGH,
        source_agent="cloud_posture",
        source_finding_id="CSPM-AWS-S3-001-alpha",
        arn="arn:aws:s3:::alpha",
        sequence=1,
    )
    b = _finding(
        control_id="2.1.4",
        severity=Severity.MEDIUM,
        source_agent="data_security",
        source_finding_id="CSPM-AWS-PUBLIC-001-beta",
        source_rule_id="s3_bucket_public",
        arn="arn:aws:s3:::beta",
        sequence=2,
        hash_tag="d5_aabbccdd",
    )
    result = aggregate_controls(
        [a, b],
        envelope=_envelope(),
        aggregated_at=datetime(2026, 5, 21, tzinfo=UTC),
    )
    assert len(result) == 1
    out = result[0]
    # Max severity across HIGH + MEDIUM = HIGH.
    assert out.severity == Severity.HIGH


def test_max_severity_across_contributors() -> None:
    """A control with contributions at LOW + HIGH lands at HIGH."""
    low = _finding(control_id="1.10", severity=Severity.LOW, sequence=1)
    high = _finding(control_id="1.10", severity=Severity.HIGH, sequence=2, hash_tag="f3_eeff0011")
    result = aggregate_controls(
        [low, high],
        envelope=_envelope(),
        aggregated_at=datetime(2026, 5, 21, tzinfo=UTC),
    )
    assert len(result) == 1
    assert result[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# FAIL-only gate
# ---------------------------------------------------------------------------


def test_medium_floor_triggers_fail_emit() -> None:
    """A control with only MEDIUM contributors is FAIL (>= MEDIUM gate)."""
    med = _finding(control_id="1.10", severity=Severity.MEDIUM)
    result = aggregate_controls(
        [med],
        envelope=_envelope(),
        aggregated_at=datetime(2026, 5, 21, tzinfo=UTC),
    )
    assert len(result) == 1


def test_mixed_controls_only_fail_controls_returned() -> None:
    """Controls A (HIGH) and B (LOW only) -> only A in output."""
    a = _finding(control_id="1.10", severity=Severity.HIGH)
    b = _finding(control_id="2.4.1", severity=Severity.LOW, sequence=2)
    result = aggregate_controls(
        [a, b],
        envelope=_envelope(),
        aggregated_at=datetime(2026, 5, 21, tzinfo=UTC),
    )
    assert len(result) == 1
    assert result[0].rule_id == "cis_aws_v3:1.10"


# ---------------------------------------------------------------------------
# Evidence shape
# ---------------------------------------------------------------------------


def test_evidence_carries_contributor_finding_ids() -> None:
    a = _finding(control_id="1.10", severity=Severity.HIGH, sequence=1)
    b = _finding(control_id="1.10", severity=Severity.MEDIUM, sequence=2, hash_tag="f3_eeff0011")
    result = aggregate_controls(
        [a, b],
        envelope=_envelope(),
        aggregated_at=datetime(2026, 5, 21, tzinfo=UTC),
    )
    ev = result[0].to_dict()["evidences"][0]
    assert ev["aggregated_status"] == "FAIL"
    assert ev["contributor_count"] == 2
    assert set(ev["contributing_finding_ids"]) == {a.finding_id, b.finding_id}


def test_evidence_carries_source_findings_provenance() -> None:
    a = _finding(
        control_id="2.1.4",
        severity=Severity.HIGH,
        source_agent="cloud_posture",
        source_finding_id="CSPM-AWS-S3-001-alpha",
        source_rule_id="CSPM-AWS-S3-001",
    )
    b = _finding(
        control_id="2.1.4",
        severity=Severity.MEDIUM,
        source_agent="data_security",
        source_finding_id="CSPM-AWS-PUBLIC-001-beta",
        source_rule_id="s3_bucket_public",
        sequence=2,
        hash_tag="d5_aabbccdd",
        arn="arn:aws:s3:::beta",
    )
    result = aggregate_controls(
        [a, b],
        envelope=_envelope(),
        aggregated_at=datetime(2026, 5, 21, tzinfo=UTC),
    )
    sources = result[0].to_dict()["evidences"][0]["contributing_source_findings"]
    agents = {s["agent"] for s in sources}
    assert agents == {"cloud_posture", "data_security"}


def test_evidence_carries_control_metadata_from_first_contributor() -> None:
    inp = _finding(control_id="1.10", severity=Severity.HIGH)
    result = aggregate_controls(
        [inp],
        envelope=_envelope(),
        aggregated_at=datetime(2026, 5, 21, tzinfo=UTC),
    )
    control_meta = result[0].to_dict()["evidences"][0]["control"]
    assert control_meta["framework"] == "cis_aws_v3"
    assert control_meta["control_id"] == "1.10"
    assert control_meta["level"] == "level_1"
    assert control_meta["required"] is True


# ---------------------------------------------------------------------------
# Resource union
# ---------------------------------------------------------------------------


def test_resources_are_unioned_and_deduped_by_arn() -> None:
    """Two contributors carrying the same arn collapse to one resource;
    distinct arns survive as separate entries."""
    a = _finding(
        control_id="2.1.4",
        severity=Severity.HIGH,
        arn="arn:aws:s3:::alpha",
        sequence=1,
    )
    b = _finding(
        control_id="2.1.4",
        severity=Severity.MEDIUM,
        arn="arn:aws:s3:::beta",
        sequence=2,
        hash_tag="d5_aabbccdd",
    )
    c = _finding(
        control_id="2.1.4",
        severity=Severity.HIGH,
        arn="arn:aws:s3:::alpha",  # duplicate
        sequence=3,
        hash_tag="f3_eeff0011",
    )
    result = aggregate_controls(
        [a, b, c],
        envelope=_envelope(),
        aggregated_at=datetime(2026, 5, 21, tzinfo=UTC),
    )
    resources = result[0].resources
    arns = {r["uid"] for r in resources}
    assert arns == {"arn:aws:s3:::alpha", "arn:aws:s3:::beta"}


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_output_ordering_is_deterministic_by_control_id() -> None:
    """Aggregated emits are ordered by control_id so reruns produce
    identical findings.json byte order."""
    a = _finding(control_id="5.2", severity=Severity.HIGH, sequence=1)
    b = _finding(control_id="1.10", severity=Severity.HIGH, sequence=2)
    c = _finding(control_id="2.1.4", severity=Severity.HIGH, sequence=3)
    result = aggregate_controls(
        [a, b, c],
        envelope=_envelope(),
        aggregated_at=datetime(2026, 5, 21, tzinfo=UTC),
    )
    control_ids = [f.rule_id for f in result]
    # Lexicographic order on "cis_aws_v3:<control_id>".
    assert control_ids == sorted(control_ids)


def test_sequence_increments_across_distinct_controls() -> None:
    a = _finding(control_id="1.10", severity=Severity.HIGH, sequence=1)
    b = _finding(control_id="2.1.4", severity=Severity.HIGH, sequence=2)
    result = aggregate_controls(
        [a, b],
        envelope=_envelope(),
        aggregated_at=datetime(2026, 5, 21, tzinfo=UTC),
    )
    seqs = [f.finding_id.split("-")[3] for f in result]
    assert seqs == ["001", "002"]


@pytest.mark.parametrize(
    "severity,expected_kept",
    [
        (Severity.CRITICAL, True),
        (Severity.HIGH, True),
        (Severity.MEDIUM, True),
        (Severity.LOW, False),
        (Severity.INFO, False),
    ],
)
def test_pass_only_omission_table_drives_fail_gate(severity: Severity, expected_kept: bool) -> None:
    inp = _finding(control_id="1.10", severity=severity)
    result = aggregate_controls(
        [inp],
        envelope=_envelope(),
        aggregated_at=datetime(2026, 5, 21, tzinfo=UTC),
    )
    if expected_kept:
        assert len(result) == 1
    else:
        assert result == ()
