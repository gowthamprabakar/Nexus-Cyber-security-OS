"""D.15 v0.2 Task 3 — Azure subscription + region discovery tests (no live Azure)."""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from multi_cloud_posture.credentials_azure import AzureCredentialResolver
from multi_cloud_posture.tools import azure_discovery
from multi_cloud_posture.tools.azure_discovery import (
    AzureDiscoveryError,
    discover_locations,
    discover_subscription_id,
)


def _resolver_with_client(client: MagicMock) -> AzureCredentialResolver:
    r = AzureCredentialResolver()
    # patch the bound method on this instance via the class (slots-safe)
    return r, patch.object(AzureCredentialResolver, "client", return_value=client)


@pytest.mark.asyncio
async def test_subscription_id_from_env_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "env-sub-123")
    client = MagicMock()
    r, p = _resolver_with_client(client)
    with p:
        assert await discover_subscription_id(r) == "env-sub-123"
    client.subscriptions.list.assert_not_called()  # env short-circuits the SDK


@pytest.mark.asyncio
async def test_subscription_id_from_list_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    client = MagicMock()
    client.subscriptions.list.return_value = [SimpleNamespace(subscription_id="sub-first")]
    r, p = _resolver_with_client(client)
    with p:
        assert await discover_subscription_id(r) == "sub-first"


@pytest.mark.asyncio
async def test_subscription_id_current_only_takes_first(monkeypatch: pytest.MonkeyPatch) -> None:
    """Q6 guard: with multiple subscriptions, the first is taken and the rest are
    NOT walked (the generator is not exhausted)."""
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    walked: list[str] = []

    def _gen() -> object:
        for sid in ("sub-1", "sub-2", "sub-3"):
            walked.append(sid)
            yield SimpleNamespace(subscription_id=sid)

    client = MagicMock()
    client.subscriptions.list.return_value = _gen()
    r, p = _resolver_with_client(client)
    with p:
        assert await discover_subscription_id(r) == "sub-1"
    assert walked == ["sub-1"]  # only the first subscription was consumed


@pytest.mark.asyncio
async def test_subscription_id_raises_when_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    client = MagicMock()
    client.subscriptions.list.return_value = []
    r, p = _resolver_with_client(client)
    with p, pytest.raises(AzureDiscoveryError, match="no Azure subscription"):
        await discover_subscription_id(r)


@pytest.mark.asyncio
async def test_locations_sorted(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock()
    client.subscriptions.list_locations.return_value = [
        SimpleNamespace(name="westus"),
        SimpleNamespace(name="eastus"),
        SimpleNamespace(name="centralus"),
    ]
    r, p = _resolver_with_client(client)
    with p:
        assert await discover_locations(r, "sub-1") == ["centralus", "eastus", "westus"]


@pytest.mark.asyncio
async def test_locations_filters_empty_names() -> None:
    client = MagicMock()
    client.subscriptions.list_locations.return_value = [
        SimpleNamespace(name="eastus"),
        SimpleNamespace(name=None),
        SimpleNamespace(name=""),
    ]
    r, p = _resolver_with_client(client)
    with p:
        assert await discover_locations(r, "sub-1") == ["eastus"]


@pytest.mark.asyncio
async def test_locations_passes_subscription_id() -> None:
    client = MagicMock()
    client.subscriptions.list_locations.return_value = []
    r, p = _resolver_with_client(client)
    with p:
        await discover_locations(r, "sub-XYZ")
    client.subscriptions.list_locations.assert_called_once_with("sub-XYZ")


def test_q6_no_multi_scope_apis_referenced() -> None:
    """Q6 structural guard: discovery references no management-group / tenant /
    multi-subscription enumeration API."""
    src = inspect.getsource(azure_discovery)
    for forbidden in ("management_group", "ManagementGroup", "tenants", "list_tenants"):
        assert forbidden not in src
