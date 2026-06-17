"""Tests for the M365 connector (D.10 SSPM PR3).

Real connector logic over a fake ``GraphClient`` (the identity-agent Azure-AD test style)
— no live Graph, no token exchange. Covers parsing + Pattern-E degradation + tri-state.
"""

from __future__ import annotations

from typing import Any

import pytest
from sspm.tools.m365 import GLOBAL_ADMIN_TEMPLATE_ID, read_m365_tenant

pytestmark = pytest.mark.asyncio


class _FakeGraph:
    """A GraphClient fake: per-resource canned collections + single objects."""

    def __init__(
        self,
        *,
        collections: dict[str, list[dict[str, Any]]] | None = None,
        objects: dict[str, dict[str, Any]] | None = None,
        fail: set[str] | None = None,
    ) -> None:
        self._collections = collections or {}
        self._objects = objects or {}
        self._fail = fail or set()

    async def get_all(self, resource: str, *, select: str | None = None) -> list[dict[str, Any]]:
        if resource in self._fail:
            raise RuntimeError(f"boom: {resource}")
        return self._collections.get(resource, [])

    async def get_one(self, resource: str) -> dict[str, Any]:
        if resource in self._fail:
            raise RuntimeError(f"boom: {resource}")
        return self._objects.get(resource, {})


def _full_graph() -> _FakeGraph:
    ga_role_id = "ga-role-1"
    return _FakeGraph(
        objects={
            "policies/identitySecurityDefaultsEnforcementPolicy": {"isEnabled": False},
            "policies/authorizationPolicy": {
                "allowInvitesFrom": "everyone",
                "defaultUserRolePermissions": {
                    "permissionGrantPoliciesAssigned": ["managePermissionGrantsForSelf"]
                },
            },
        },
        collections={
            "identity/conditionalAccessPolicies": [],
            "directoryRoles": [
                {"id": ga_role_id, "roleTemplateId": GLOBAL_ADMIN_TEMPLATE_ID},
            ],
            f"directoryRoles/{ga_role_id}/members": [{"id": "u1"}, {"id": "u2"}],
            "oauth2PermissionGrants": [
                {"clientId": "app-1", "scope": "User.Read Directory.ReadWrite.All"},
                {"clientId": "app-2", "scope": "User.Read"},
            ],
        },
    )


async def test_reads_full_tenant_inventory() -> None:
    inv = await read_m365_tenant(tenant_id="contoso", graph=_full_graph())

    assert inv.tenant_id == "contoso"
    assert inv.security_defaults_enabled is False
    assert inv.allow_invites_from == "everyone"
    assert inv.user_consent_allowed is True
    assert inv.conditional_access_policy_count == 0
    assert inv.global_admin_count == 2
    assert {g.client_id for g in inv.oauth_grants} == {"app-1", "app-2"}
    app1 = next(g for g in inv.oauth_grants if g.client_id == "app-1")
    assert "Directory.ReadWrite.All" in app1.scopes


async def test_tristate_when_objects_unreadable() -> None:
    # authorizationPolicy + security defaults unreadable → None / "unknown", recorded degraded.
    graph = _FakeGraph(
        fail={
            "policies/identitySecurityDefaultsEnforcementPolicy",
            "policies/authorizationPolicy",
        }
    )
    inv = await read_m365_tenant(tenant_id="contoso", graph=graph)
    assert inv.security_defaults_enabled is None
    assert inv.allow_invites_from == "unknown"
    assert inv.user_consent_allowed is None
    assert len(inv.degraded) == 2


async def test_no_global_admin_role_yields_none_count() -> None:
    graph = _FakeGraph(collections={"directoryRoles": [{"id": "other", "displayName": "Reader"}]})
    inv = await read_m365_tenant(tenant_id="contoso", graph=graph)
    assert inv.global_admin_count is None
