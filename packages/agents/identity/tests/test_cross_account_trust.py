"""W3 red-team bank — cross-account trust detection precision."""

from datetime import UTC, datetime

from identity.tools.aws_iam import IamRole
from identity.tools.cross_account import cross_account_trust_grants

_DATE = datetime(2026, 7, 1, tzinfo=UTC)
_HOME = "111111111111"
_FOREIGN = "999999999999"
_ROLE = f"arn:aws:iam::{_HOME}:role/partner-access"


def _role(principal_aws) -> IamRole:
    return IamRole(
        arn=_ROLE,
        name="partner-access",
        role_id="AROA1",
        create_date=_DATE,
        last_used_at=None,
        assume_role_policy_document={
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": principal_aws}, "Action": "sts:AssumeRole"}
            ]
        },
    )


def test_foreign_account_root_is_cross_account():
    out = cross_account_trust_grants([_role(f"arn:aws:iam::{_FOREIGN}:root")])
    assert out == [(f"arn:aws:iam::{_FOREIGN}:root", _ROLE)]


def test_anonymous_wildcard_principal_is_cross_account():
    assert cross_account_trust_grants([_role("*")]) == [("*", _ROLE)]


def test_list_of_principals_mixed():
    out = cross_account_trust_grants(
        [_role([f"arn:aws:iam::{_HOME}:root", f"arn:aws:iam::{_FOREIGN}:user/x"])]
    )
    assert out == [(f"arn:aws:iam::{_FOREIGN}:user/x", _ROLE)]  # only the foreign one


# --- traps → no grant ---


def test_trap_same_account_principal():
    assert cross_account_trust_grants([_role(f"arn:aws:iam::{_HOME}:root")]) == []


def test_trap_service_principal():
    role = IamRole(
        arn=_ROLE,
        name="r",
        role_id="AROA2",
        create_date=_DATE,
        last_used_at=None,
        assume_role_policy_document={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ]
        },
    )
    assert cross_account_trust_grants([role]) == []


def test_trap_deny_statement():
    role = IamRole(
        arn=_ROLE,
        name="r",
        role_id="AROA3",
        create_date=_DATE,
        last_used_at=None,
        assume_role_policy_document={
            "Statement": [{"Effect": "Deny", "Principal": {"AWS": f"arn:aws:iam::{_FOREIGN}:root"}}]
        },
    )
    assert cross_account_trust_grants([role]) == []
