"""Tests for `identity.tools.permission_paths` (D.2 Task 6 resolver)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from identity.tools.aws_iam import (
    IamGroup,
    IamRole,
    IamUser,
    IdentityListing,
    SimulationDecision,
)
from identity.tools.permission_paths import (
    EffectiveGrant,
    find_admin_principals,
    grants_by_principal,
    is_admin_action,
    resolve_effective_grants,
)

NOW = datetime(2026, 5, 11, tzinfo=UTC)
ALICE = "arn:aws:iam::123456789012:user/alice"
BOB = "arn:aws:iam::123456789012:user/bob"
LAMBDA_ROLE = "arn:aws:iam::123456789012:role/LambdaExecutionRole"
ADMINS_GROUP = "arn:aws:iam::123456789012:group/admins"


def _listing() -> IdentityListing:
    alice = IamUser(
        arn=ALICE,
        name="alice",
        user_id="AIDA-ALICE",
        create_date=NOW,
        last_used_at=NOW,
        attached_policy_arns=("arn:aws:iam::aws:policy/AdministratorAccess",),
        group_memberships=("admins",),
    )
    bob = IamUser(
        arn=BOB,
        name="bob",
        user_id="AIDA-BOB",
        create_date=NOW,
        last_used_at=NOW,
    )
    lambda_role = IamRole(
        arn=LAMBDA_ROLE,
        name="LambdaExecutionRole",
        role_id="AROA-LAMBDA",
        create_date=NOW,
        last_used_at=NOW,
        assume_role_policy_document={},
        attached_policy_arns=("arn:aws:iam::aws:policy/AWSLambdaBasicExecutionRole",),
    )
    admins = IamGroup(
        arn=ADMINS_GROUP,
        name="admins",
        group_id="AGPA-ADMINS",
        create_date=NOW,
        member_user_names=("alice",),
        attached_policy_arns=("arn:aws:iam::aws:policy/IAMFullAccess",),
    )
    return IdentityListing(
        users=(alice, bob),
        roles=(lambda_role,),
        groups=(admins,),
    )


def _decision(
    *,
    principal_arn: str = ALICE,
    action: str = "s3:GetObject",
    resource: str = "*",
    decision: str = "allowed",
    matched: tuple[str, ...] = (),
) -> SimulationDecision:
    return SimulationDecision(
        principal_arn=principal_arn,
        action=action,
        resource=resource,
        decision=decision,
        matched_statement_ids=matched,
    )


# ---------------------------- decision-to-effect mapping -----------------


@pytest.mark.asyncio
async def test_allowed_decision_yields_allow_grant() -> None:
    grants = resolve_effective_grants(_listing(), [_decision(decision="allowed")])
    assert len(grants) == 1
    assert grants[0].effect == "Allow"
    assert grants[0].principal_arn == ALICE


def test_explicit_deny_yields_deny_grant() -> None:
    grants = resolve_effective_grants(
        _listing(),
        [_decision(action="iam:CreateUser", decision="explicitDeny")],
    )
    assert len(grants) == 1
    assert grants[0].effect == "Deny"


def test_implicit_deny_dropped() -> None:
    grants = resolve_effective_grants(
        _listing(),
        [
            _decision(action="s3:GetObject", decision="allowed"),
            _decision(action="ec2:TerminateInstances", decision="implicitDeny"),
        ],
    )
    assert len(grants) == 1
    assert grants[0].action == "s3:GetObject"


def test_decision_for_unknown_principal_dropped() -> None:
    """A decision for a principal not in the listing must be dropped."""
    decisions = [_decision(principal_arn="arn:aws:iam::1:user/ghost")]
    grants = resolve_effective_grants(_listing(), decisions)
    assert grants == ()


# ---------------------------- admin classification -----------------------


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("*", True),
        ("*:*", True),
        ("iam:*", True),
        ("s3:*", True),
        ("s3:GetObject", False),
        ("iam:CreateUser", False),
        ("", False),
    ],
)
def test_is_admin_action(action: str, expected: bool) -> None:
    assert is_admin_action(action) is expected


def test_admin_action_flagged_in_grant() -> None:
    grants = resolve_effective_grants(
        _listing(),
        [_decision(action="iam:*", decision="allowed")],
    )
    assert grants[0].is_admin is True


def test_non_admin_action_not_flagged() -> None:
    grants = resolve_effective_grants(
        _listing(),
        [_decision(action="s3:GetObject", decision="allowed")],
    )
    assert grants[0].is_admin is False


# ---------------------------- multi-principal grouping -------------------


def test_grants_by_principal_groups_correctly() -> None:
    decisions = [
        _decision(principal_arn=ALICE, action="iam:CreateUser"),
        _decision(principal_arn=BOB, action="s3:GetObject"),
        _decision(principal_arn=ALICE, action="iam:DeleteUser"),
    ]
    grants = resolve_effective_grants(_listing(), decisions)
    grouped = grants_by_principal(grants)

    assert set(grouped) == {ALICE, BOB}
    assert len(grouped[ALICE]) == 2
    assert len(grouped[BOB]) == 1


def test_grants_by_principal_preserves_input_order() -> None:
    decisions = [_decision(action=f"svc:Op{i}", decision="allowed") for i in range(5)]
    grants = resolve_effective_grants(_listing(), decisions)
    grouped = grants_by_principal(grants)
    actions = [g.action for g in grouped[ALICE]]
    assert actions == [f"svc:Op{i}" for i in range(5)]


# ---------------------------- admin-principal helper ---------------------


def test_find_admin_principals_returns_arns_with_admin_allow() -> None:
    decisions = [
        _decision(principal_arn=ALICE, action="iam:*", decision="allowed"),
        _decision(principal_arn=BOB, action="s3:GetObject", decision="allowed"),
    ]
    grants = resolve_effective_grants(_listing(), decisions)
    assert find_admin_principals(grants) == (ALICE,)


def test_find_admin_principals_skips_explicit_deny_admin() -> None:
    """An explicitDeny on a wildcard action shouldn't mark the principal admin."""
    decisions = [
        _decision(principal_arn=ALICE, action="*:*", decision="explicitDeny"),
    ]
    grants = resolve_effective_grants(_listing(), decisions)
    assert find_admin_principals(grants) == ()


def test_find_admin_principals_dedupes() -> None:
    decisions = [
        _decision(principal_arn=ALICE, action="iam:*", decision="allowed"),
        _decision(principal_arn=ALICE, action="*:*", decision="allowed"),
    ]
    grants = resolve_effective_grants(_listing(), decisions)
    assert find_admin_principals(grants) == (ALICE,)


# ---------------------------- source policy attribution ------------------


def test_source_policy_arns_carried_through() -> None:
    grants = resolve_effective_grants(
        _listing(),
        [
            _decision(
                principal_arn=ALICE,
                action="iam:*",
                matched=("AdministratorAccess",),
            )
        ],
    )
    assert grants[0].source_policy_arns == ("AdministratorAccess",)


# ---------------------------- shape invariants ---------------------------


def test_effective_grant_is_frozen() -> None:
    import dataclasses

    g = EffectiveGrant(
        principal_arn=ALICE,
        action="s3:GetObject",
        resource_pattern="*",
        effect="Allow",
        source_policy_arns=(),
        is_admin=False,
    )
    assert dataclasses.is_dataclass(g)
    with pytest.raises(dataclasses.FrozenInstanceError):
        g.action = "mutated"  # type: ignore[misc]


def test_empty_decisions_returns_empty_tuple() -> None:
    assert resolve_effective_grants(_listing(), []) == ()


def test_resolve_returns_tuple_not_list() -> None:
    grants = resolve_effective_grants(_listing(), [_decision()])
    assert isinstance(grants, tuple)
