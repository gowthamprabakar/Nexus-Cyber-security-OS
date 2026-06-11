"""Cross-tenant audit authorization — code-level enforcement (audit v0.2 Task 14, WI-F11/Q6).

Audit chains are strictly tenant-isolated (F.5 RLS + the Task-10 engine filter). A query that
spans **more than one tenant** — or all tenants — is privileged: it requires the ``admin``
role. ``assert_admin_for_cross_tenant`` is the hard, code-level gate (mirroring the Task-13
read-only guard); any cross-tenant query from a non-admin caller raises.

The guard accepts anything exposing ``is_cross_tenant()`` (the ``TypedAuditFilter`` seam from
Task 9, or the ``CrossTenantQuery`` here), so single-tenant filters pass for any role.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol

ADMIN_ROLE = "admin"


class SupportsCrossTenant(Protocol):
    def is_cross_tenant(self) -> bool: ...


class CrossTenantAuditAuthorizationError(RuntimeError):
    """Raised when a non-admin caller attempts a cross-tenant audit query (WI-F11)."""


@dataclass(frozen=True, slots=True)
class CrossTenantQuery:
    """A query scope that may span several tenants (or all of them)."""

    tenant_ids: frozenset[str] = field(default_factory=frozenset)
    all_tenants: bool = False

    def is_cross_tenant(self) -> bool:
        return self.all_tenants or len(self.tenant_ids) > 1


def cross_tenant_query(
    *, tenant_ids: Iterable[str] = (), all_tenants: bool = False
) -> CrossTenantQuery:
    return CrossTenantQuery(tenant_ids=frozenset(tenant_ids), all_tenants=all_tenants)


def assert_admin_for_cross_tenant(query: SupportsCrossTenant, caller_role: str) -> None:
    """Hard guard — a cross-tenant query requires the admin role (Q6 + F.5 RLS defense-in-depth).
    Single-tenant queries pass for any role."""
    if query.is_cross_tenant() and caller_role != ADMIN_ROLE:
        raise CrossTenantAuditAuthorizationError(
            f"Cross-tenant audit query requires the {ADMIN_ROLE!r} role; "
            f"caller has {caller_role!r}. Per Q6 invariant + F.5 RLS defense-in-depth."
        )
