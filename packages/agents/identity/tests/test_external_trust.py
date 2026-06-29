"""Path 8 — offline cross-account-trust detection (`_externally_trusted_arns`).

A role's ``AssumeRolePolicyDocument`` is already in the listing, so external trust is
derivable with no Access-Analyzer call (the online path). External = an ``Allow`` statement
trusting a foreign account or ``*``; same-account and service principals are internal.
Pure evaluation (no cloud).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from identity.agent import _externally_trusted_arns
from identity.tools.aws_iam import IamRole, IdentityListing

_NOW = datetime(2026, 6, 22, tzinfo=UTC)
_OWN = "123456789012"


def _trust(principal: Any) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}],
    }


def _role(name: str, trust: dict[str, Any]) -> IamRole:
    return IamRole(
        arn=f"arn:aws:iam::{_OWN}:role/{name}",
        name=name,
        role_id=f"AROA{name}",
        create_date=_NOW,
        last_used_at=None,
        assume_role_policy_document=trust,
    )


def _listing(*roles: IamRole) -> IdentityListing:
    return IdentityListing(users=(), roles=roles, groups=())


def test_foreign_account_root_is_external() -> None:
    role = _role("cross", _trust({"AWS": "arn:aws:iam::999999999999:root"}))
    assert _externally_trusted_arns(_listing(role)) == [role.arn]


def test_public_wildcard_principal_is_external() -> None:
    role = _role("public", _trust("*"))
    assert _externally_trusted_arns(_listing(role)) == [role.arn]


def test_aws_wildcard_principal_is_external() -> None:
    role = _role("public", _trust({"AWS": "*"}))
    assert _externally_trusted_arns(_listing(role)) == [role.arn]


def test_same_account_principal_is_internal() -> None:
    role = _role("internal", _trust({"AWS": f"arn:aws:iam::{_OWN}:root"}))
    assert _externally_trusted_arns(_listing(role)) == []


def test_service_principal_is_internal() -> None:
    role = _role("svc", _trust({"Service": "ec2.amazonaws.com"}))
    assert _externally_trusted_arns(_listing(role)) == []


def test_deny_statement_is_ignored() -> None:
    role = _role("deny", _trust({"AWS": "arn:aws:iam::999999999999:root"}))
    role.assume_role_policy_document["Statement"][0]["Effect"] = "Deny"
    assert _externally_trusted_arns(_listing(role)) == []


def test_mixed_principal_list_flags_on_foreign() -> None:
    role = _role(
        "mixed",
        _trust({"AWS": [f"arn:aws:iam::{_OWN}:root", "arn:aws:iam::999999999999:root"]}),
    )
    assert _externally_trusted_arns(_listing(role)) == [role.arn]
