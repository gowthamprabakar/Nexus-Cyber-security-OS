"""D.2 v0.2 Task 10 — Azure AD (Microsoft Graph) users + groups enumeration.

The `GraphReader` seam is injected with a fake so the enumeration is exercised
without a live tenant or httpx; the httpx-backed `_HttpGraphReader` is a thin
transport wrapper over the same seam.
"""

from __future__ import annotations

from typing import Any

import pytest
from identity.tools.azure_ad import (
    AzureAdGroup,
    AzureAdListing,
    AzureAdListingError,
    AzureAdServicePrincipal,
    AzureAdUser,
    azure_ad_list_identities,
)


class _FakeGraphReader:
    def __init__(self, data: dict[str, list[dict[str, Any]]]) -> None:
        self._data = data
        self.calls: list[tuple[str, str | None]] = []

    async def get_all(self, resource: str, *, select: str | None = None) -> list[dict[str, Any]]:
        self.calls.append((resource, select))
        return self._data.get(resource, [])


class _BoomReader:
    async def get_all(self, resource: str, *, select: str | None = None) -> list[dict[str, Any]]:
        raise RuntimeError("token request-id=secret tenant leaked")


def _seed() -> _FakeGraphReader:
    return _FakeGraphReader(
        {
            "users": [
                {
                    "id": "u1",
                    "userPrincipalName": "alice@contoso.com",
                    "displayName": "Alice",
                    "accountEnabled": True,
                },
                {
                    "id": "u2",
                    "userPrincipalName": "bob@contoso.com",
                    "displayName": "Bob",
                    "accountEnabled": False,
                },
            ],
            "groups": [
                {"id": "g1", "displayName": "Admins", "securityEnabled": True},
                {"id": "g2", "displayName": "All Staff", "securityEnabled": False},
            ],
            "servicePrincipals": [
                {
                    "id": "sp1",
                    "appId": "app-1",
                    "displayName": "CI Deployer",
                    "servicePrincipalType": "Application",
                    "accountEnabled": True,
                },
                {
                    "id": "sp2",
                    "appId": "app-2",
                    "displayName": "vm-mi",
                    "servicePrincipalType": "ManagedIdentity",
                    "accountEnabled": True,
                },
            ],
        }
    )


@pytest.mark.asyncio
async def test_lists_users_and_groups() -> None:
    listing = await azure_ad_list_identities(graph=_seed())

    assert isinstance(listing, AzureAdListing)
    assert {u.user_principal_name for u in listing.users} == {
        "alice@contoso.com",
        "bob@contoso.com",
    }
    assert {g.display_name for g in listing.groups} == {"Admins", "All Staff"}


@pytest.mark.asyncio
async def test_account_enabled_flag_parsed() -> None:
    listing = await azure_ad_list_identities(graph=_seed())
    by_upn = {u.user_principal_name: u for u in listing.users}
    assert by_upn["alice@contoso.com"].account_enabled is True
    assert by_upn["bob@contoso.com"].account_enabled is False  # disabled account surfaced


@pytest.mark.asyncio
async def test_security_enabled_flag_parsed() -> None:
    listing = await azure_ad_list_identities(graph=_seed())
    by_name = {g.display_name: g for g in listing.groups}
    assert by_name["Admins"].security_enabled is True
    assert by_name["All Staff"].security_enabled is False


@pytest.mark.asyncio
async def test_requests_the_right_select_fields() -> None:
    reader = _seed()
    await azure_ad_list_identities(graph=reader)
    calls = dict(reader.calls)
    assert calls["users"] == "id,userPrincipalName,displayName,accountEnabled"
    assert calls["groups"] == "id,displayName,securityEnabled"
    assert calls["servicePrincipals"] == "id,appId,displayName,servicePrincipalType,accountEnabled"


@pytest.mark.asyncio
async def test_lists_service_principals() -> None:
    listing = await azure_ad_list_identities(graph=_seed())
    assert {sp.display_name for sp in listing.service_principals} == {"CI Deployer", "vm-mi"}
    assert {sp.app_id for sp in listing.service_principals} == {"app-1", "app-2"}


@pytest.mark.asyncio
async def test_managed_identities_filter() -> None:
    listing = await azure_ad_list_identities(graph=_seed())
    mis = listing.managed_identities
    assert len(mis) == 1
    assert mis[0] == AzureAdServicePrincipal(
        id="sp2",
        app_id="app-2",
        display_name="vm-mi",
        sp_type="ManagedIdentity",
        account_enabled=True,
    )
    # Application SPs are not managed identities.
    assert all(sp.sp_type == "ManagedIdentity" for sp in mis)


@pytest.mark.asyncio
async def test_no_service_principals_yields_empty() -> None:
    listing = await azure_ad_list_identities(graph=_FakeGraphReader({"users": [], "groups": []}))
    assert listing.service_principals == ()
    assert listing.managed_identities == ()


@pytest.mark.asyncio
async def test_empty_directory() -> None:
    listing = await azure_ad_list_identities(graph=_FakeGraphReader({}))
    assert listing.users == ()
    assert listing.groups == ()


@pytest.mark.asyncio
async def test_graph_error_is_wrapped_secret_free() -> None:
    with pytest.raises(AzureAdListingError) as exc:
        await azure_ad_list_identities(graph=_BoomReader())
    # the wrapper message names the failure but the test asserts it is raised as
    # the typed error (the secret-bearing detail rides in __cause__, not the type).
    assert isinstance(exc.value, AzureAdListingError)


@pytest.mark.asyncio
async def test_missing_fields_default_safely() -> None:
    reader = _FakeGraphReader({"users": [{"id": "u9"}], "groups": [{"id": "g9"}]})
    listing = await azure_ad_list_identities(graph=reader)
    assert listing.users[0] == AzureAdUser(
        id="u9", user_principal_name="", display_name="", account_enabled=False
    )
    assert listing.groups[0] == AzureAdGroup(id="g9", display_name="", security_enabled=False)
