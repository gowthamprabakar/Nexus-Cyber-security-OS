"""Tests for the Azure OpenAI connector parse + posture rules (D.11 PR3)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from aispm.posture.azure import AzureAiFindingType, evaluate_azure_ai
from aispm.tools.azure_ai import AzureAiInventory, AzureOpenAiAccount, inventory_from_reader
from shared.fabric.envelope import NexusEnvelope

_NOW = datetime(2026, 6, 17, 12, 0, 0, tzinfo=UTC)


class _FakeAzureReader:
    def __init__(self, accounts: list[dict[str, Any]]) -> None:
        self._a = accounts

    def openai_accounts(self) -> list[dict[str, Any]]:
        return self._a


def _envelope() -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id="c",
        tenant_id="cust_test",
        agent_id="aispm",
        nlah_version="0.1.0",
        model_pin="deterministic",
        charter_invocation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
    )


def test_parse_and_tristate() -> None:
    reader = _FakeAzureReader(
        [
            {
                "name": "openai-prod",
                "public_network_access": True,
                "network_default_allow": True,
                "cmk_encrypted": False,
                "local_auth_disabled": False,
            },
            {"name": ""},  # skipped
        ]
    )
    inv = inventory_from_reader(reader, subscription_id="sub-1")
    assert [a.name for a in inv.accounts] == ["openai-prod"]
    assert inv.accounts[0].public_network_access is True


def test_parses_model_data_blob() -> None:
    # The fine-tune / grounding Blob link for path 10 (gap #13 cross-cloud).
    reader = _FakeAzureReader(
        [
            {
                "name": "gpt",
                "public_network_access": True,
                "model_data_account": "acmestorage",
                "model_data_container": "training",
            }
        ]
    )
    inv = inventory_from_reader(reader, subscription_id="sub-1")
    assert inv.accounts[0].model_data_account == "acmestorage"
    assert inv.accounts[0].model_data_container == "training"


def test_all_four_checks_fire() -> None:
    inv = AzureAiInventory(
        subscription_id="sub-1",
        accounts=(
            AzureOpenAiAccount(
                name="openai-prod",
                public_network_access=True,
                network_default_allow=True,
                cmk_encrypted=False,
                local_auth_disabled=False,
            ),
        ),
    )
    findings = evaluate_azure_ai(inv, envelope=_envelope(), detected_at=_NOW)
    assert {f.finding_type for f in findings} == {t.value for t in AzureAiFindingType}
    assert all(f.to_dict()["class_uid"] == 2003 for f in findings)


def test_clean_and_unknown_skip() -> None:
    clean = AzureAiInventory(
        subscription_id="sub-1",
        accounts=(
            AzureOpenAiAccount(
                name="ok",
                public_network_access=False,
                network_default_allow=False,
                cmk_encrypted=True,
                local_auth_disabled=True,
            ),
        ),
    )
    assert evaluate_azure_ai(clean, envelope=_envelope(), detected_at=_NOW) == []
    unknown = AzureAiInventory(
        subscription_id="sub-1",
        accounts=(
            AzureOpenAiAccount(
                name="u",
                public_network_access=None,
                network_default_allow=None,
                cmk_encrypted=None,
                local_auth_disabled=None,
            ),
        ),
    )
    assert evaluate_azure_ai(unknown, envelope=_envelope(), detected_at=_NOW) == []
