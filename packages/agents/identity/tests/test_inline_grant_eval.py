"""v0.4 Stage 1.5 — per-role inline-grant evaluation depth (D.2).

`_synthesize_admin_grants` now evaluates the inline-policy *documents* (#723) for
wildcard-admin statements, so a principal that is admin via an inline policy — with
no attached AdministratorAccess — is caught. Pure evaluation (no cloud).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from identity.agent import _synthesize_admin_grants
from identity.tools.aws_iam import IamGroup, IamRole, IamUser, IdentityListing

_ADMIN_DOC: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
_SCOPED_DOC: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}],
}
_NOW = datetime(2026, 6, 17, tzinfo=UTC)


def _user(name: str, *, inline: tuple[tuple[str, dict[str, Any]], ...] = ()) -> IamUser:
    return IamUser(
        arn=f"arn:aws:iam::123456789012:user/{name}",
        name=name,
        user_id=f"AIDA{name}",
        create_date=_NOW,
        last_used_at=None,
        inline_policies=inline,
    )


def _role(name: str, *, inline: tuple[tuple[str, dict[str, Any]], ...] = ()) -> IamRole:
    return IamRole(
        arn=f"arn:aws:iam::123456789012:role/{name}",
        name=name,
        role_id=f"AROA{name}",
        create_date=_NOW,
        last_used_at=None,
        assume_role_policy_document={},
        inline_policies=inline,
    )


def test_user_admin_via_inline_only_is_detected() -> None:
    listing = IdentityListing(
        users=(_user("dana", inline=(("dana-admin", _ADMIN_DOC),)),), roles=(), groups=()
    )
    grants = _synthesize_admin_grants(listing)
    assert len(grants) == 1
    assert grants[0].is_admin is True
    assert "inline:dana-admin" in grants[0].source_policy_arns


def test_role_admin_via_inline_only_is_detected() -> None:
    listing = IdentityListing(
        users=(), roles=(_role("svc", inline=(("svc-admin", _ADMIN_DOC),)),), groups=()
    )
    grants = _synthesize_admin_grants(listing)
    assert [g.principal_arn for g in grants] == ["arn:aws:iam::123456789012:role/svc"]
    assert "inline:svc-admin" in grants[0].source_policy_arns


def test_scoped_inline_policy_is_not_admin() -> None:
    listing = IdentityListing(
        users=(_user("ed", inline=(("ed-readonly", _SCOPED_DOC),)),), roles=(), groups=()
    )
    assert _synthesize_admin_grants(listing) == []


def test_user_inherits_inline_admin_via_group() -> None:
    group = IamGroup(
        arn="arn:aws:iam::123456789012:group/admins",
        name="admins",
        group_id="AGPAadmins",
        create_date=_NOW,
        inline_policies=(("grp-admin", _ADMIN_DOC),),
    )
    user = IamUser(
        arn="arn:aws:iam::123456789012:user/fred",
        name="fred",
        user_id="AIDAfred",
        create_date=_NOW,
        last_used_at=None,
        group_memberships=("admins",),
    )
    listing = IdentityListing(users=(user,), roles=(), groups=(group,))
    grants = _synthesize_admin_grants(listing)
    principals = {g.principal_arn for g in grants}
    assert "arn:aws:iam::123456789012:user/fred" in principals  # inherited inline admin
    assert "arn:aws:iam::123456789012:group/admins" in principals
