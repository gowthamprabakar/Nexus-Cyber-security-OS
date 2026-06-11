"""compliance v0.2 Task 6 — PASS attestation finding schema + emission (WI-C6)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

# Reuse the framework enum + AffectedResource from the agent's schema surface.
from cloud_posture.schemas import AffectedResource
from compliance.schemas import (
    OCSF_COMPLIANCE_PASSED_STATUS_ID as PASS_ID,
)
from compliance.schemas import (
    ComplianceFramework,
    MissingPositiveEvidenceError,
    build_pass_finding,
)
from shared.fabric.envelope import NexusEnvelope

_T = datetime(2026, 6, 11, 12, 0, 0, tzinfo=UTC)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="corr_xyz",
        tenant_id="cust_test",
        agent_id="compliance",
        nlah_version="0.2.0",
        model_pin="deterministic",
        charter_invocation_id="invocation_001",
    )


def _affected() -> list[AffectedResource]:
    return [
        AffectedResource(
            cloud="aws",
            account_id="111122223333",
            region="us-east-1",
            resource_type="account",
            resource_id="111122223333",
            arn="arn:aws:iam::111122223333:root",
        )
    ]


def _attestation() -> dict[str, object]:
    return {
        "kind": "compliance_pass",
        "control_id": "1.4",
        "source_finding_ids": [],
        "attested_at": _T.isoformat(),
        "evidence_payload": {"checked_rules": ["CSPM-AWS-IAM-002"], "all_passing": True},
    }


def _build(**over: object) -> object:
    kwargs: dict[str, object] = {
        "finding_id": "COMPLIANCE-CIS_AWS_V3-1.4-001-pass",
        "framework": ComplianceFramework.CIS_AWS_V3,
        "control_id": "1.4",
        "title": "CIS-AWS 1.4 attested PASS",
        "description": "no failing source findings for the control's mapped rules",
        "affected": _affected(),
        "detected_at": _T,
        "envelope": _envelope(),
        "attestation": _attestation(),
    }
    kwargs.update(over)
    return build_pass_finding(**kwargs)  # type: ignore[arg-type]


def test_pass_finding_is_class_uid_2003() -> None:
    d = _build().to_dict()
    assert d["class_uid"] == 2003


def test_pass_status_and_status_id() -> None:
    d = _build().to_dict()
    assert d["compliance"]["status"] == "Passed"
    assert d["compliance"]["status_id"] == PASS_ID == 1


def test_pass_severity_is_informational() -> None:
    assert _build().to_dict()["severity"] == "Info"


def test_attestation_in_evidences() -> None:
    evidences = _build().to_dict()["evidences"]
    assert len(evidences) == 1 and evidences[0]["kind"] == "compliance_pass"
    assert evidences[0]["evidence_payload"]["all_passing"] is True


def test_empty_attestation_rejected() -> None:
    # WI-C6 / pause-trigger #13: PASS must include positive evidence, not just absence of FAIL.
    with pytest.raises(MissingPositiveEvidenceError, match="positive evidence"):
        _build(attestation={})


def test_bad_finding_id_rejected() -> None:
    with pytest.raises(ValueError, match="finding_id"):
        _build(finding_id="not a valid id")


def test_empty_affected_rejected() -> None:
    with pytest.raises(ValueError, match="affected"):
        _build(affected=[])
