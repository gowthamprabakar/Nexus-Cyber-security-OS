"""Tests for the AI-SPM OCSF schemas (D.11 PR1, ADR-020 — dual class 2003 + 2004)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from aispm.schemas import (
    AiAffectedResource,
    FindingsReport,
    NexusEnvelope,
    Severity,
    build_detection_finding,
    build_posture_finding,
)
from shared.fabric.envelope import unwrap_ocsf

_NOW = datetime(2026, 6, 17, 12, 0, 0, tzinfo=UTC)


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="c",
        tenant_id="cust_test",
        agent_id="aispm",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
    )


def _resource() -> AiAffectedResource:
    return AiAffectedResource(
        provider="sagemaker",
        account_id="111122223333",
        resource_type="ai_service",
        resource_id="endpoint/prod",
    )


def test_posture_finding_is_ocsf_2003() -> None:
    f = build_posture_finding(
        finding_id="AISPM-SAGEMAKER-001-prod",
        rule_id="AISPM-SM-PUBLIC",
        finding_type="aispm_sagemaker_endpoint_public",
        severity=Severity.HIGH,
        title="SageMaker endpoint is public",
        description="The endpoint is reachable outside a VPC.",
        affected=[_resource()],
        detected_at=_NOW,
        envelope=_envelope(),
    )
    d = f.to_dict()
    assert d["class_uid"] == 2003
    assert d["compliance"]["control"] == "AISPM-SM-PUBLIC"
    assert d["finding_info"]["types"] == ["aispm_sagemaker_endpoint_public"]
    assert d["resources"][0]["uid"] == "sagemaker:111122223333:endpoint/prod"
    _, env = unwrap_ocsf(d)
    assert env.tenant_id == "cust_test"
    assert f.class_uid == 2003 and f.severity is Severity.HIGH


def test_detection_finding_is_ocsf_2004() -> None:
    f = build_detection_finding(
        finding_id="AISPM-BEDROCK-001-jailbreak",
        finding_type="aispm_promptinjection_jailbreak",
        severity=Severity.CRITICAL,
        title="Prompt-injection: jailbreak succeeded",
        description="A Garak probe elicited restricted behaviour.",
        affected=[
            AiAffectedResource(
                provider="bedrock",
                account_id="111122223333",
                resource_type="ai_model",
                resource_id="anthropic.claude",
            )
        ],
        detected_at=_NOW,
        envelope=_envelope(),
    )
    d = f.to_dict()
    assert d["class_uid"] == 2004
    assert "compliance" not in d  # detection findings carry no compliance block
    assert f.finding_type == "aispm_promptinjection_jailbreak"


def test_bad_finding_id_rejected() -> None:
    with pytest.raises(ValueError, match="finding_id must match"):
        build_posture_finding(
            finding_id="bad-id",
            rule_id="r",
            finding_type="t",
            severity=Severity.LOW,
            title="t",
            description="d",
            affected=[_resource()],
            detected_at=_NOW,
            envelope=_envelope(),
        )


def test_empty_affected_rejected() -> None:
    with pytest.raises(ValueError, match="affected resources"):
        build_detection_finding(
            finding_id="AISPM-BEDROCK-001-x",
            finding_type="t",
            severity=Severity.LOW,
            title="t",
            description="d",
            affected=[],
            detected_at=_NOW,
            envelope=_envelope(),
        )


def test_report_add_and_count() -> None:
    report = FindingsReport(
        agent="aispm",
        agent_version="0.1.0",
        customer_id="cust_test",
        run_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        scan_started_at=_NOW,
        scan_completed_at=_NOW,
    )
    report.add_finding(
        build_posture_finding(
            finding_id="AISPM-VERTEX-001-prod",
            rule_id="AISPM-VX-PUBLIC",
            finding_type="aispm_vertex_endpoint_public",
            severity=Severity.HIGH,
            title="t",
            description="d",
            affected=[_resource()],
            detected_at=_NOW,
            envelope=_envelope(),
        )
    )
    assert report.total == 1
    assert report.count_by_severity()["high"] == 1
