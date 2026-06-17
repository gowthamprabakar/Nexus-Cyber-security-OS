"""Tests for the AWS AI-service posture rules (D.11 PR2)."""

from __future__ import annotations

from datetime import UTC, datetime

from aispm.posture.aws import AwsAiFindingType, evaluate_aws_ai
from aispm.tools.aws_ai import AwsAiInventory, SageMakerEndpoint, SageMakerNotebook
from shared.fabric.envelope import NexusEnvelope

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


def _types(findings: list) -> set[str]:
    return {f.finding_type for f in findings}


def test_all_six_checks_fire() -> None:
    inv = AwsAiInventory(
        account_id="111122223333",
        region="us-east-1",
        sagemaker_endpoints=(
            SageMakerEndpoint(
                name="prod",
                data_capture_enabled=False,
                kms_encrypted=False,
                network_isolated=False,
                model_name="m1",
            ),
        ),
        sagemaker_notebooks=(SageMakerNotebook(name="nb1", direct_internet_access=True),),
        bedrock_logging_enabled=False,
        bedrock_guardrail_count=0,
    )
    findings = evaluate_aws_ai(inv, envelope=_envelope(), detected_at=_NOW)
    assert _types(findings) == {t.value for t in AwsAiFindingType}  # all 6
    assert all(f.to_dict()["class_uid"] == 2003 for f in findings)
    ids = {f.finding_id for f in findings}
    assert "AISPM-BEDROCK-005-111122223333" in ids
    assert "AISPM-SAGEMAKER-001-111122223333-prod" in ids


def test_clean_account_yields_no_findings() -> None:
    inv = AwsAiInventory(
        account_id="111122223333",
        region="us-east-1",
        sagemaker_endpoints=(
            SageMakerEndpoint(
                name="prod",
                data_capture_enabled=True,
                kms_encrypted=True,
                network_isolated=True,
                model_name="m1",
            ),
        ),
        sagemaker_notebooks=(SageMakerNotebook(name="nb1", direct_internet_access=False),),
        bedrock_logging_enabled=True,
        bedrock_guardrail_count=2,
    )
    assert evaluate_aws_ai(inv, envelope=_envelope(), detected_at=_NOW) == []


def test_unknown_tristate_never_flags() -> None:
    inv = AwsAiInventory(
        account_id="111122223333",
        region="us-east-1",
        sagemaker_endpoints=(
            SageMakerEndpoint(
                name="prod",
                data_capture_enabled=None,
                kms_encrypted=None,
                network_isolated=None,
                model_name="m1",
            ),
        ),
        sagemaker_notebooks=(SageMakerNotebook(name="nb1", direct_internet_access=None),),
        bedrock_logging_enabled=None,  # unreadable → no bedrock findings at all
        bedrock_guardrail_count=0,
    )
    assert evaluate_aws_ai(inv, envelope=_envelope(), detected_at=_NOW) == []
