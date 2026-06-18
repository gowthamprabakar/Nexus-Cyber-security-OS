"""Azure OpenAI discovery connector (D.11 AI-SPM PR3, operator Q1 cloud #2).

Reads a subscription's Azure OpenAI (Cognitive Services) accounts into a typed
``AzureAiInventory`` via the azure-mgmt-cognitiveservices SDK. Same shape as the AWS
connector: a thin :class:`AzureAiReader` protocol (extracted dicts) + a pure
:func:`inventory_from_reader`; the live ``_MgmtAzureAiReader`` is the gated live path. Auth
follows the charter credential contract (azure-identity DefaultAzureCredential; the
subscription id is a source identifier, no secret material). No torch.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Protocol


class AzureAiReader(Protocol):
    """Source of already-extracted Azure-OpenAI account dicts — real SDK or fake."""

    def openai_accounts(self) -> list[dict[str, Any]]: ...


@dataclass(frozen=True, slots=True)
class AzureOpenAiAccount:
    name: str
    public_network_access: bool | None  # True = "Enabled"
    network_default_allow: bool | None  # networkAcls.defaultAction == "Allow"
    cmk_encrypted: bool | None  # encryption.keySource == "Microsoft.KeyVault"
    local_auth_disabled: bool | None  # disableLocalAuth


@dataclass(frozen=True, slots=True)
class AzureAiInventory:
    subscription_id: str
    accounts: tuple[AzureOpenAiAccount, ...] = field(default_factory=tuple)
    degraded: tuple[dict[str, str], ...] = field(default_factory=tuple)


def inventory_from_reader(reader: AzureAiReader, *, subscription_id: str) -> AzureAiInventory:
    """Pure: build a typed :class:`AzureAiInventory` from a reader's extracted dicts."""
    accounts = tuple(
        AzureOpenAiAccount(
            name=str(a.get("name", "")),
            public_network_access=a.get("public_network_access"),
            network_default_allow=a.get("network_default_allow"),
            cmk_encrypted=a.get("cmk_encrypted"),
            local_auth_disabled=a.get("local_auth_disabled"),
        )
        for a in reader.openai_accounts()
        if a.get("name")
    )
    return AzureAiInventory(subscription_id=subscription_id, accounts=accounts)


class _MgmtAzureAiReader:
    """Live azure-mgmt-cognitiveservices reader (gated live path; NOT exercised in CI)."""

    def __init__(self, *, subscription_id: str) -> None:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient

        self._client = CognitiveServicesManagementClient(DefaultAzureCredential(), subscription_id)

    def openai_accounts(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for acct in self._client.accounts.list():
            if getattr(acct, "kind", "") != "OpenAI":
                continue
            props = getattr(acct, "properties", None)
            network_acls = getattr(props, "network_acls", None)
            encryption = getattr(props, "encryption", None)
            out.append(
                {
                    "name": getattr(acct, "name", ""),
                    "public_network_access": getattr(props, "public_network_access", None)
                    == "Enabled",
                    "network_default_allow": (
                        getattr(network_acls, "default_action", None) == "Allow"
                        if network_acls is not None
                        else None
                    ),
                    "cmk_encrypted": (
                        getattr(encryption, "key_source", None) == "Microsoft.KeyVault"
                        if encryption is not None
                        else False
                    ),
                    "local_auth_disabled": getattr(props, "disable_local_auth", None),
                }
            )
        return out


async def read_azure_ai(
    *,
    subscription_id: str,
    reader: AzureAiReader | None = None,
) -> AzureAiInventory:
    """Read a subscription's Azure OpenAI posture into a typed inventory."""
    if reader is not None:
        return inventory_from_reader(reader, subscription_id=subscription_id)
    return await asyncio.to_thread(
        lambda: inventory_from_reader(
            _MgmtAzureAiReader(subscription_id=subscription_id), subscription_id=subscription_id
        )
    )


__all__ = [
    "AzureAiInventory",
    "AzureAiReader",
    "AzureOpenAiAccount",
    "inventory_from_reader",
    "read_azure_ai",
]
