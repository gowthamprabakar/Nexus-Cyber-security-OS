"""remediation v0.2 Task 18 — assert_tenant_scoped tests (WI-A18/H6)."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from remediation.invariants.tenant_scoped import (
    TenantScopeViolationError,
    assert_tenant_scoped,
)


@dataclass
class _Contractish:
    customer_id: str


def test_string_tenant_ok() -> None:
    assert_tenant_scoped("cust-1")


def test_contract_like_ok() -> None:
    assert_tenant_scoped(_Contractish(customer_id="cust-1"))


def test_empty_string_raises() -> None:
    with pytest.raises(TenantScopeViolationError, match="tenant scope"):
        assert_tenant_scoped("")


def test_whitespace_only_raises() -> None:
    with pytest.raises(TenantScopeViolationError):
        assert_tenant_scoped("   ")


def test_empty_customer_id_raises() -> None:
    with pytest.raises(TenantScopeViolationError):
        assert_tenant_scoped(_Contractish(customer_id=""))


def test_missing_customer_id_attr_raises() -> None:
    with pytest.raises(TenantScopeViolationError):
        assert_tenant_scoped(object())


def test_message_mentions_cross_tenant_forbidden() -> None:
    with pytest.raises(TenantScopeViolationError, match="cross-tenant remediation is forbidden"):
        assert_tenant_scoped("")
