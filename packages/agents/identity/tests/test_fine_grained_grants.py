"""Path 4 — offline fine-grained S3 access extraction (`_fine_grained_grants`).

Beyond admin synthesis: a principal's customer-managed / inline policy documents (already in
the listing) are walked for Allow statements granting an S3 read on a CONCRETE bucket ARN, so
a least-privilege-violating principal (specific access to a sensitive bucket, NOT admin) is
caught. Pure evaluation (no cloud). Bucket ARNs are normalized to the spine key.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from identity.agent import _fine_grained_grants
from identity.tools.aws_iam import IamPolicy, IamRole, IamUser, IdentityListing

_NOW = datetime(2026, 6, 22, tzinfo=UTC)
_OWN = "123456789012"


def _read_doc(resource: Any) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": resource}],
    }


def _role(name: str, *, inline: tuple[tuple[str, dict[str, Any]], ...] = ()) -> IamRole:
    return IamRole(
        arn=f"arn:aws:iam::{_OWN}:role/{name}",
        name=name,
        role_id=f"AROA{name}",
        create_date=_NOW,
        last_used_at=None,
        assume_role_policy_document={},
        inline_policies=inline,
    )


def _user(name: str, *, attached: tuple[str, ...] = ()) -> IamUser:
    return IamUser(
        arn=f"arn:aws:iam::{_OWN}:user/{name}",
        name=name,
        user_id=f"AIDA{name}",
        create_date=_NOW,
        last_used_at=None,
        attached_policy_arns=attached,
    )


def test_inline_concrete_bucket_grant_is_extracted() -> None:
    role = _role("reader", inline=(("read-sensitive", _read_doc("arn:aws:s3:::secret-bucket/*")),))
    listing = IdentityListing(users=(), roles=(role,), groups=())
    assert _fine_grained_grants(listing) == [(role.arn, "arn:aws:s3:::secret-bucket")]


def test_attached_customer_managed_policy_is_resolved() -> None:
    policy = IamPolicy(
        arn=f"arn:aws:iam::{_OWN}:policy/read",
        name="read",
        policy_id="ANPAread",
        default_version_id="v1",
        document=_read_doc("arn:aws:s3:::data-lake"),
    )
    user = _user("dana", attached=(policy.arn,))
    listing = IdentityListing(users=(user,), roles=(), groups=(), policies=(policy,))
    assert _fine_grained_grants(listing) == [(user.arn, "arn:aws:s3:::data-lake")]


def test_wildcard_resource_is_skipped() -> None:
    # Resource "*" is broad, not fine-grained-to-a-bucket → not a path-4 signal.
    role = _role("broad", inline=(("all", _read_doc("*")),))
    listing = IdentityListing(users=(), roles=(role,), groups=())
    assert _fine_grained_grants(listing) == []


def test_non_s3_read_action_is_ignored() -> None:
    doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::b/*"}
        ],
    }
    role = _role("writer", inline=(("write", doc),))
    listing = IdentityListing(users=(), roles=(role,), groups=())
    assert _fine_grained_grants(listing) == []


def test_deny_statement_is_ignored() -> None:
    doc = _read_doc("arn:aws:s3:::b/*")
    doc["Statement"][0]["Effect"] = "Deny"
    role = _role("deny", inline=(("d", doc),))
    listing = IdentityListing(users=(), roles=(role,), groups=())
    assert _fine_grained_grants(listing) == []


def test_object_suffix_is_stripped_to_bucket_arn() -> None:
    role = _role("deep", inline=(("d", _read_doc("arn:aws:s3:::b/deep/path/key.txt")),))
    listing = IdentityListing(users=(), roles=(role,), groups=())
    assert _fine_grained_grants(listing) == [(role.arn, "arn:aws:s3:::b")]
