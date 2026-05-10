"""Role-Based Access Control — `(Role, Action) → bool` permission table.

Resolves F.4 plan **Q3** (RBAC model). Phase 1 ships three roles
(admin / operator / auditor) with a hard-coded permission table here in
code. Per-customer custom roles are deferred to Phase 1c when there's a
real signal that the three-role split can't carry the workload.

Why hard-coded:

- Surface area is tiny (~10 actions for v0.1) so an in-code table is
  faster to reason about than a DB-backed `permissions` table.
- The audit story is cleaner: a code review is the only way to grant a
  role new powers; the change is git-traceable per ADR-002.
- DB-backed permissions become viable once we add custom roles in
  Phase 1c — and the migration is a one-shot dump of this dict.
"""

from __future__ import annotations

from enum import StrEnum

from control_plane.tenants.models import Role


class Action(StrEnum):
    """The set of actions the control plane gates on. Grow as agents land."""

    READ_FINDINGS = "read_findings"
    APPROVE_TIER_2 = "approve_tier_2"
    EXECUTE_TIER_1 = "execute_tier_1"
    MANAGE_USERS = "manage_users"
    MANAGE_TENANT = "manage_tenant"
    VIEW_AUDIT_LOG = "view_audit_log"
    EXPORT_DATA = "export_data"


_PERMISSIONS: dict[Role, frozenset[Action]] = {
    Role.ADMIN: frozenset(Action),
    Role.OPERATOR: frozenset(
        {
            Action.READ_FINDINGS,
            Action.APPROVE_TIER_2,
            Action.EXECUTE_TIER_1,
            Action.VIEW_AUDIT_LOG,
            Action.EXPORT_DATA,
        }
    ),
    Role.AUDITOR: frozenset(
        {
            Action.READ_FINDINGS,
            Action.VIEW_AUDIT_LOG,
        }
    ),
}


def permission_for(role: Role, action: Action) -> bool:
    """Return True iff `role` is allowed to perform `action`."""
    return action in _PERMISSIONS[role]


def actions_for(role: Role) -> frozenset[Action]:
    """Return the full set of actions `role` is permitted to perform."""
    return _PERMISSIONS[role]


__all__ = [
    "Action",
    "actions_for",
    "permission_for",
]
