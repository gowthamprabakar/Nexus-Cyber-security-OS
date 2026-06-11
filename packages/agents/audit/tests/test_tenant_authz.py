"""audit v0.2 Task 14 — cross-tenant audit authorization tests (WI-F11/Q6)."""

from __future__ import annotations

import pytest
from audit.query.typed_filter import TypedAuditFilter
from audit.tenant_authz import (
    ADMIN_ROLE,
    CrossTenantAuditAuthorizationError,
    CrossTenantQuery,
    assert_admin_for_cross_tenant,
    cross_tenant_query,
)

_TENANT_A = "01HV0T0000000000000000TENA"
_TENANT_B = "01HV0T0000000000000000TENB"


def test_single_tenant_query_not_cross_tenant() -> None:
    assert CrossTenantQuery(tenant_ids=frozenset({_TENANT_A})).is_cross_tenant() is False


def test_multi_tenant_is_cross_tenant() -> None:
    q = cross_tenant_query(tenant_ids=[_TENANT_A, _TENANT_B])
    assert q.is_cross_tenant() is True


def test_all_tenants_is_cross_tenant() -> None:
    assert cross_tenant_query(all_tenants=True).is_cross_tenant() is True


def test_cross_tenant_non_admin_rejected() -> None:
    q = cross_tenant_query(all_tenants=True)
    with pytest.raises(CrossTenantAuditAuthorizationError, match="requires the 'admin' role"):
        assert_admin_for_cross_tenant(q, "viewer")


def test_cross_tenant_admin_allowed() -> None:
    q = cross_tenant_query(tenant_ids=[_TENANT_A, _TENANT_B])
    assert_admin_for_cross_tenant(q, ADMIN_ROLE)  # does not raise


def test_single_tenant_any_role_allowed() -> None:
    q = cross_tenant_query(tenant_ids=[_TENANT_A])
    assert_admin_for_cross_tenant(q, "viewer")  # single-tenant -> no admin needed


def test_typed_filter_seam_passes_for_non_admin() -> None:
    # TypedAuditFilter is always single-tenant -> never needs admin.
    assert_admin_for_cross_tenant(TypedAuditFilter(tenant_id=_TENANT_A), "viewer")


def test_multi_tenant_non_admin_rejected() -> None:
    q = cross_tenant_query(tenant_ids=[_TENANT_A, _TENANT_B])
    with pytest.raises(CrossTenantAuditAuthorizationError):
        assert_admin_for_cross_tenant(q, "operator")
