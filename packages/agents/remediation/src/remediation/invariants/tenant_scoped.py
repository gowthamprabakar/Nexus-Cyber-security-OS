"""Tenant-scoped invariant (remediation v0.2 Task 18, WI-A18 / H6).

Every ``read_findings`` and every ``apply_patch`` carries the ``customer_id`` from the
ExecutionContract — cross-tenant remediation is FORBIDDEN (a tenant's findings can only ever
produce mutations in that tenant's cluster). ``assert_tenant_scoped`` is the hard guard, mirroring
curiosity's tenant invariant: a missing/empty tenant id raises before any read or mutation. The
guard accepts a bare tenant string or any object exposing a ``customer_id`` attribute (the
ExecutionContract).
"""

from __future__ import annotations

from typing import Any


class TenantScopeViolationError(RuntimeError):
    """Raised when a remediation op is attempted without an explicit tenant scope (WI-A18)."""


def _extract_tenant_id(scope: Any) -> str:
    if isinstance(scope, str):
        return scope
    tenant = getattr(scope, "customer_id", None)
    return tenant if isinstance(tenant, str) else ""


def assert_tenant_scoped(scope: Any) -> None:
    """Hard guard — raise if ``scope`` carries no non-empty tenant id (WI-A18/H6).

    ``scope`` is a tenant-id string or an object with ``customer_id`` (the ExecutionContract).
    Cross-tenant remediation is forbidden — a tenant only ever remediates its own cluster.
    """
    tenant_id = _extract_tenant_id(scope)
    if not tenant_id or not tenant_id.strip():
        raise TenantScopeViolationError(
            "remediation op missing tenant scope; every read_findings + apply_patch is "
            "tenant-scoped and cross-tenant remediation is forbidden (WI-A18)."
        )
