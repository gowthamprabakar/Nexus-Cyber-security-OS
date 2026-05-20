"""Tests — ``compliance.scorer`` (Task 9).

Validates the canonical severity scorer:

  - Level 1 + required    -> HIGH
  - Level 1 + recommended -> MEDIUM
  - Level 2 + required    -> MEDIUM
  - Level 2 + recommended -> LOW

Plus the rebuild semantics: identity preserved on no-op, re-stamp
keeps every other payload field verbatim (envelope + finding_id +
evidence + resources).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from compliance.schemas import (
    AffectedResource,
    ComplianceFinding,
    ComplianceFramework,
    Severity,
    build_finding,
)
from compliance.scorer import score_findings, score_severity_from_evidence
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


def _affected() -> list[AffectedResource]:
    return [
        AffectedResource(
            cloud="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_iam_user",
            resource_id="alice",
            arn="arn:aws:iam::123456789012:user/alice",
        )
    ]


def _finding(
    *,
    control_id: str = "1.10",
    severity: Severity = Severity.HIGH,
    level: str = "level_1",
    required: bool = True,
) -> ComplianceFinding:
    control_token = control_id.replace(".", "_")
    return build_finding(
        finding_id=f"COMPLIANCE-CIS_AWS_V3-{control_token}-001-aggregated",
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id=control_id,
        severity=severity,
        title="x",
        description="y",
        affected=_affected(),
        detected_at=datetime(2026, 5, 21, tzinfo=UTC),
        envelope=_envelope(),
        evidence={
            "control": {
                "framework": "cis_aws_v3",
                "control_id": control_id,
                "level": level,
                "required": required,
            }
        },
    )


# ---------------------------------------------------------------------------
# Pure score_severity_from_evidence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "level,required,expected",
    [
        ("level_1", True, Severity.HIGH),
        ("level_1", False, Severity.MEDIUM),
        ("level_2", True, Severity.MEDIUM),
        ("level_2", False, Severity.LOW),
    ],
)
def test_score_severity_table(level: str, required: bool, expected: Severity) -> None:
    ev = {"control": {"level": level, "required": required}}
    assert score_severity_from_evidence(ev) == expected


def test_score_severity_missing_evidence_collapses_to_low() -> None:
    assert score_severity_from_evidence({}) == Severity.LOW


def test_score_severity_garbage_control_block_collapses_to_low() -> None:
    assert score_severity_from_evidence({"control": "garbage"}) == Severity.LOW


def test_score_severity_unknown_level_collapses_to_low() -> None:
    ev = {"control": {"level": "level_99", "required": True}}
    assert score_severity_from_evidence(ev) == Severity.LOW


def test_score_severity_missing_required_defaults_to_true() -> None:
    """Absent `required` flag is treated as `True` (the bundled YAML
    default), so Level 1 collapses to HIGH not MEDIUM."""
    ev = {"control": {"level": "level_1"}}
    assert score_severity_from_evidence(ev) == Severity.HIGH


# ---------------------------------------------------------------------------
# score_findings batch
# ---------------------------------------------------------------------------


def test_score_findings_empty_input() -> None:
    assert score_findings([]) == ()


def test_score_findings_identity_preserved_when_canonical() -> None:
    """Input already at HIGH on a Level-1-required control -> identity."""
    f = _finding(
        control_id="1.10",
        severity=Severity.HIGH,
        level="level_1",
        required=True,
    )
    result = score_findings([f])
    assert result[0] is f


def test_score_findings_restamps_when_input_diverges() -> None:
    """Input at LOW on a Level-1-required control gets re-stamped to HIGH."""
    f = _finding(
        control_id="1.10",
        severity=Severity.LOW,
        level="level_1",
        required=True,
    )
    result = score_findings([f])
    assert len(result) == 1
    assert result[0] is not f
    assert result[0].severity == Severity.HIGH
    # finding_id (and the rest of the payload) is preserved.
    assert result[0].finding_id == f.finding_id


def test_score_findings_restamps_preserve_envelope() -> None:
    f = _finding(
        control_id="1.10",
        severity=Severity.LOW,
        level="level_1",
        required=True,
    )
    result = score_findings([f])
    re = result[0]
    assert re.envelope.tenant_id == "acme"
    assert re.envelope.correlation_id == "00000000-0000-0000-0000-00000000d6d6"


def test_score_findings_severity_id_round_trip() -> None:
    """Verify OCSF severity_id integer matches the new severity string label."""
    findings = [
        _finding(severity=Severity.LOW, level="level_1", required=True),  # -> HIGH
        _finding(severity=Severity.HIGH, level="level_2", required=False),  # -> LOW
    ]
    result = score_findings(findings)
    severity_ids = [int(f.to_dict()["severity_id"]) for f in result]
    severity_strings = [str(f.to_dict()["severity"]).lower() for f in result]
    assert severity_ids == [4, 2]  # HIGH=4, LOW=2
    assert severity_strings == ["high", "low"]


def test_score_findings_batch_mixed_inputs() -> None:
    """Five findings spanning the full Level x required matrix get correct
    canonical severities."""
    inputs = [
        _finding(control_id="1.1", severity=Severity.LOW, level="level_1", required=True),
        _finding(control_id="1.2", severity=Severity.LOW, level="level_1", required=False),
        _finding(control_id="2.1", severity=Severity.LOW, level="level_2", required=True),
        _finding(control_id="2.2", severity=Severity.LOW, level="level_2", required=False),
    ]
    result = score_findings(inputs)
    severities = [f.severity for f in result]
    assert severities == [
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.MEDIUM,
        Severity.LOW,
    ]
