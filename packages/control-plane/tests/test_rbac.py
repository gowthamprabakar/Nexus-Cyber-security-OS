"""Tests for `control_plane.auth.rbac`.

The matrix test parametrizes every (role, action) pair so the truth
table is the unit under test — adding a new action without updating
`_PERMISSIONS` will trip the parametrized assertions immediately.
"""

from __future__ import annotations

import pytest
from control_plane.auth.rbac import Action, actions_for, permission_for
from control_plane.tenants.models import Role

# Expected (role, action) → permitted truth table. Mirrors the production
# table; if production diverges, this file fails. That's the point.
_EXPECTED: dict[tuple[Role, Action], bool] = {}
for action in Action:
    _EXPECTED[(Role.ADMIN, action)] = True
for action in Action:
    _EXPECTED[(Role.OPERATOR, action)] = action in {
        Action.READ_FINDINGS,
        Action.APPROVE_TIER_2,
        Action.EXECUTE_TIER_1,
        Action.VIEW_AUDIT_LOG,
        Action.EXPORT_DATA,
    }
for action in Action:
    _EXPECTED[(Role.AUDITOR, action)] = action in {
        Action.READ_FINDINGS,
        Action.VIEW_AUDIT_LOG,
    }


@pytest.mark.parametrize(("role", "action"), list(_EXPECTED))
def test_permission_matrix(role: Role, action: Action) -> None:
    expected = _EXPECTED[(role, action)]
    assert permission_for(role, action) is expected, (
        f"{role.value} should {'have' if expected else 'NOT have'} {action.value}"
    )


def test_admin_has_every_action() -> None:
    assert actions_for(Role.ADMIN) == frozenset(Action)


def test_auditor_is_read_only() -> None:
    actions = actions_for(Role.AUDITOR)
    assert Action.READ_FINDINGS in actions
    # No mutation actions for auditors.
    forbidden = {
        Action.APPROVE_TIER_2,
        Action.EXECUTE_TIER_1,
        Action.MANAGE_USERS,
        Action.MANAGE_TENANT,
        Action.EXPORT_DATA,
    }
    assert forbidden.isdisjoint(actions)


def test_operator_cannot_manage_tenants_or_users() -> None:
    actions = actions_for(Role.OPERATOR)
    assert Action.MANAGE_TENANT not in actions
    assert Action.MANAGE_USERS not in actions


def test_action_enum_round_trips_through_string() -> None:
    """Action is a StrEnum so it can be serialized via `.value` and rebuilt."""
    for action in Action:
        assert Action(action.value) is action


def test_actions_for_returns_frozenset() -> None:
    assert isinstance(actions_for(Role.ADMIN), frozenset)


def test_permission_table_covers_every_role() -> None:
    """Every Role must be wired up; calling `actions_for` shouldn't KeyError."""
    for role in Role:
        actions_for(role)  # raises KeyError if role missing from _PERMISSIONS
