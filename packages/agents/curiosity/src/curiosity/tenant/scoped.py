"""Tenant-scoped invariant — code-level (curiosity v0.2 Task 15, WI-X13/H5 — NEW).

The first of D.12's **three NEW** curiosity-specific invariants. Per **H5** every curiosity scan
is **tenant-scoped, always** — cross-tenant aggregation is FORBIDDEN by the privacy contract at
v0.2, v0.3, and every future version (never to be relaxed). ``assert_tenant_scoped`` is the hard
guard at the scan entry point + every sibling-state read: a missing/empty tenant id raises before
any store access. The agent's contract carries the tenant as ``customer_id`` (there is no separate
ScanContract type), so the guard accepts either a bare tenant string or any object exposing a
``customer_id`` attribute.
"""

from __future__ import annotations

from typing import Any


class TenantScopeViolationError(RuntimeError):
    """Raised when a curiosity scan is attempted without an explicit tenant scope (WI-X13)."""


def _extract_tenant_id(scope: Any) -> str:
    if isinstance(scope, str):
        return scope
    tenant = getattr(scope, "customer_id", None)
    return tenant if isinstance(tenant, str) else ""


def assert_tenant_scoped(scope: Any) -> None:
    """Hard guard — raise if ``scope`` carries no non-empty tenant id (H5/WI-X13).

    ``scope`` is either a tenant-id string or an object with a ``customer_id`` (e.g. the
    ExecutionContract). Cross-tenant aggregation is forbidden by the privacy contract — always.
    """
    tenant_id = _extract_tenant_id(scope)
    if not tenant_id or not tenant_id.strip():
        raise TenantScopeViolationError(
            "Curiosity scan missing tenant scope. Per H5: tenant-scoped, always. "
            "Cross-tenant aggregation is forbidden by the privacy contract (WI-X13)."
        )
