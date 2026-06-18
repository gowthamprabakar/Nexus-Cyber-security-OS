"""AWS AI-service posture rules (D.11 AI-SPM PR2).

Evaluates a typed :class:`~aispm.tools.aws_ai.AwsAiInventory` into OCSF 2003 posture
findings — 6 real checks (4 SageMaker + 2 Bedrock). Honest tri-state: a ``None`` (unknown)
value NEVER produces a finding. ``finding_id`` follows ``AISPM-<PROVIDER>-<NNN>-<context>``.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from aispm.schemas import AiAffectedResource, AiFinding, Severity, build_posture_finding

if TYPE_CHECKING:
    from shared.fabric.envelope import NexusEnvelope

    from aispm.tools.aws_ai import AwsAiInventory


class AwsAiFindingType(StrEnum):
    SAGEMAKER_INFERENCE_LOGGING_DISABLED = "aispm_sagemaker_inference_logging_disabled"
    SAGEMAKER_ENDPOINT_NO_CMK = "aispm_sagemaker_endpoint_no_cmk"
    SAGEMAKER_MODEL_NO_NETWORK_ISOLATION = "aispm_sagemaker_model_no_network_isolation"
    SAGEMAKER_NOTEBOOK_DIRECT_INTERNET = "aispm_sagemaker_notebook_direct_internet"
    BEDROCK_INVOCATION_LOGGING_DISABLED = "aispm_bedrock_invocation_logging_disabled"
    BEDROCK_NO_GUARDRAILS = "aispm_bedrock_no_guardrails"


def _ctx(*parts: str) -> str:
    joined = "-".join(parts)
    return re.sub(r"[^a-z0-9_-]+", "-", joined.lower()).strip("-") or "account"


def evaluate_aws_ai(
    inventory: AwsAiInventory,
    *,
    envelope: NexusEnvelope,
    detected_at: datetime,
) -> list[AiFinding]:
    """Run the 6 AWS-AI posture checks over the typed inventory."""
    out: list[AiFinding] = []
    acct = inventory.account_id

    def _svc(resource_id: str) -> list[AiAffectedResource]:
        return [
            AiAffectedResource(
                provider="sagemaker",
                account_id=acct,
                resource_type="ai_service",
                resource_id=resource_id,
            )
        ]

    def _add(
        provider_tok: str,
        n: str,
        rule: str,
        ft: AwsAiFindingType,
        sev: Severity,
        title: str,
        desc: str,
        affected: list[AiAffectedResource],
    ) -> None:
        out.append(
            build_posture_finding(
                finding_id=f"AISPM-{provider_tok}-{n}-{_ctx(acct, affected[0].resource_id)}",
                rule_id=rule,
                finding_type=ft,
                severity=sev,
                title=title,
                description=desc,
                affected=affected,
                detected_at=detected_at,
                envelope=envelope,
            )
        )

    for ep in inventory.sagemaker_endpoints:
        if ep.data_capture_enabled is False:
            _add(
                "SAGEMAKER",
                "001",
                "AISPM-SM-DATACAPTURE",
                AwsAiFindingType.SAGEMAKER_INFERENCE_LOGGING_DISABLED,
                Severity.MEDIUM,
                "SageMaker endpoint inference logging (data capture) is disabled",
                f"Endpoint {ep.name} in account {acct} has data capture off.",
                _svc(ep.name),
            )
        if ep.kms_encrypted is False:
            _add(
                "SAGEMAKER",
                "002",
                "AISPM-SM-CMK",
                AwsAiFindingType.SAGEMAKER_ENDPOINT_NO_CMK,
                Severity.LOW,
                "SageMaker endpoint is not encrypted with a customer-managed KMS key",
                f"Endpoint {ep.name} in account {acct} uses no CMK.",
                _svc(ep.name),
            )
        if ep.network_isolated is False:
            _add(
                "SAGEMAKER",
                "003",
                "AISPM-SM-NETISO",
                AwsAiFindingType.SAGEMAKER_MODEL_NO_NETWORK_ISOLATION,
                Severity.HIGH,
                "SageMaker model has no network isolation",
                f"Model {ep.model_name} (endpoint {ep.name}) is not network-isolated.",
                [
                    AiAffectedResource(
                        provider="sagemaker",
                        account_id=acct,
                        resource_type="ai_model",
                        resource_id=ep.model_name or ep.name,
                    )
                ],
            )

    for nb in inventory.sagemaker_notebooks:
        if nb.direct_internet_access is True:
            _add(
                "SAGEMAKER",
                "004",
                "AISPM-SM-NOTEBOOK-INTERNET",
                AwsAiFindingType.SAGEMAKER_NOTEBOOK_DIRECT_INTERNET,
                Severity.HIGH,
                "SageMaker notebook has direct internet access",
                f"Notebook {nb.name} in account {acct} has direct internet access enabled.",
                _svc(nb.name),
            )

    # Bedrock account-level checks (only when Bedrock state was readable).
    if inventory.bedrock_logging_enabled is False:
        out.append(
            build_posture_finding(
                finding_id=f"AISPM-BEDROCK-005-{_ctx(acct)}",
                rule_id="AISPM-BR-LOGGING",
                finding_type=AwsAiFindingType.BEDROCK_INVOCATION_LOGGING_DISABLED,
                severity=Severity.MEDIUM,
                title="Bedrock model-invocation logging is disabled",
                description=f"Account {acct} has Bedrock invocation logging off.",
                affected=[
                    AiAffectedResource(
                        provider="bedrock",
                        account_id=acct,
                        resource_type="ai_service",
                        resource_id="bedrock",
                    )
                ],
                detected_at=detected_at,
                envelope=envelope,
            )
        )
    if inventory.bedrock_logging_enabled is not None and inventory.bedrock_guardrail_count == 0:
        out.append(
            build_posture_finding(
                finding_id=f"AISPM-BEDROCK-006-{_ctx(acct)}",
                rule_id="AISPM-BR-GUARDRAILS",
                finding_type=AwsAiFindingType.BEDROCK_NO_GUARDRAILS,
                severity=Severity.MEDIUM,
                title="Bedrock has no guardrails configured",
                description=f"Account {acct} has zero Bedrock guardrails.",
                affected=[
                    AiAffectedResource(
                        provider="bedrock",
                        account_id=acct,
                        resource_type="ai_service",
                        resource_id="bedrock",
                    )
                ],
                detected_at=detected_at,
                envelope=envelope,
            )
        )
    return out


__all__ = ["AwsAiFindingType", "evaluate_aws_ai"]
