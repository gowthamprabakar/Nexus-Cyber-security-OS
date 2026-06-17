"""Azure OpenAI posture rules (D.11 AI-SPM PR3).

Evaluates a typed :class:`~aispm.tools.azure_ai.AzureAiInventory` into OCSF 2003 findings —
4 checks. Honest tri-state: ``None`` (unknown) never flags. ``finding_id``
``AISPM-AZUREOPENAI-<NNN>-<context>``.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from aispm.schemas import AiAffectedResource, AiFinding, Severity, build_posture_finding

if TYPE_CHECKING:
    from shared.fabric.envelope import NexusEnvelope

    from aispm.tools.azure_ai import AzureAiInventory


class AzureAiFindingType(StrEnum):
    PUBLIC_NETWORK_ACCESS = "aispm_azureopenai_public_network_access"
    NETWORK_DEFAULT_ALLOW = "aispm_azureopenai_network_default_allow"
    NO_CMK = "aispm_azureopenai_no_cmk"
    LOCAL_AUTH_ENABLED = "aispm_azureopenai_local_auth_enabled"


def _ctx(*parts: str) -> str:
    joined = "-".join(parts)
    return re.sub(r"[^a-z0-9_-]+", "-", joined.lower()).strip("-") or "account"


def evaluate_azure_ai(
    inventory: AzureAiInventory,
    *,
    envelope: NexusEnvelope,
    detected_at: datetime,
) -> list[AiFinding]:
    """Run the 4 Azure OpenAI posture checks over the typed inventory."""
    out: list[AiFinding] = []
    sub = inventory.subscription_id

    def _add(
        acct: str, n: str, rule: str, ft: AzureAiFindingType, sev: Severity, title: str, desc: str
    ) -> None:
        out.append(
            build_posture_finding(
                finding_id=f"AISPM-AZUREOPENAI-{n}-{_ctx(sub, acct)}",
                rule_id=rule,
                finding_type=ft,
                severity=sev,
                title=title,
                description=desc,
                affected=[
                    AiAffectedResource(
                        provider="azure_openai",
                        account_id=sub,
                        resource_type="ai_service",
                        resource_id=acct,
                    )
                ],
                detected_at=detected_at,
                envelope=envelope,
            )
        )

    for acct in inventory.accounts:
        if acct.public_network_access is True:
            _add(
                acct.name,
                "001",
                "AISPM-AOAI-PUBLIC",
                AzureAiFindingType.PUBLIC_NETWORK_ACCESS,
                Severity.HIGH,
                "Azure OpenAI account allows public network access",
                f"Account {acct.name} in subscription {sub} has public network access enabled.",
            )
        if acct.network_default_allow is True:
            _add(
                acct.name,
                "002",
                "AISPM-AOAI-NETACL",
                AzureAiFindingType.NETWORK_DEFAULT_ALLOW,
                Severity.MEDIUM,
                "Azure OpenAI network ACL default action is Allow",
                f"Account {acct.name} defaults to allowing network access.",
            )
        if acct.cmk_encrypted is False:
            _add(
                acct.name,
                "003",
                "AISPM-AOAI-CMK",
                AzureAiFindingType.NO_CMK,
                Severity.LOW,
                "Azure OpenAI account is not encrypted with a customer-managed key",
                f"Account {acct.name} uses a Microsoft-managed key.",
            )
        if acct.local_auth_disabled is False:
            _add(
                acct.name,
                "004",
                "AISPM-AOAI-LOCALAUTH",
                AzureAiFindingType.LOCAL_AUTH_ENABLED,
                Severity.MEDIUM,
                "Azure OpenAI account allows key-based (local) auth",
                f"Account {acct.name} permits API-key auth (local auth not disabled).",
            )
    return out


__all__ = ["AzureAiFindingType", "evaluate_azure_ai"]
