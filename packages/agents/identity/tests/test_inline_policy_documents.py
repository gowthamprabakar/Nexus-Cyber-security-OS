"""v0.4 Stage 1.5 — inline-policy DOCUMENT fetch (not just names).

Real AWS-IAM backend via moto: seed users/roles/groups with inline policies,
enumerate, and assert each principal's ``inline_policies`` carries the decoded
policy *document* (so per-role effective-permission evaluation can read inline
grants), alongside the existing name-only ``inline_policy_names``.
"""

from __future__ import annotations

import boto3
import pytest
from identity.tools.aws_iam import aws_iam_list_identities
from moto import mock_aws

_INLINE_DOC = (
    '{"Version":"2012-10-17","Statement":'
    '[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}'
)


def _seed(iam: object) -> None:
    iam.create_user(UserName="dana")  # type: ignore[attr-defined]
    iam.put_user_policy(  # type: ignore[attr-defined]
        UserName="dana", PolicyName="dana-inline", PolicyDocument=_INLINE_DOC
    )
    iam.create_role(  # type: ignore[attr-defined]
        RoleName="svc",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
    )
    iam.put_role_policy(  # type: ignore[attr-defined]
        RoleName="svc", PolicyName="svc-inline", PolicyDocument=_INLINE_DOC
    )
    iam.create_group(GroupName="ops")  # type: ignore[attr-defined]
    iam.put_group_policy(  # type: ignore[attr-defined]
        GroupName="ops", PolicyName="ops-inline", PolicyDocument=_INLINE_DOC
    )


@pytest.mark.asyncio
async def test_inline_policy_documents_captured_for_user_role_group() -> None:
    with mock_aws():
        _seed(boto3.client("iam"))
        listing = await aws_iam_list_identities()

    dana = next(u for u in listing.users if u.name == "dana")
    svc = next(r for r in listing.roles if r.name == "svc")
    ops = next(g for g in listing.groups if g.name == "ops")

    for principal, policy_name in ((dana, "dana-inline"), (svc, "svc-inline"), (ops, "ops-inline")):
        # name still captured (back-compat)
        assert policy_name in principal.inline_policy_names
        # document now captured + decoded
        docs = dict(principal.inline_policies)
        assert policy_name in docs
        statement = docs[policy_name]["Statement"][0]
        assert statement["Action"] == "s3:GetObject"
        assert statement["Effect"] == "Allow"


@pytest.mark.asyncio
async def test_no_inline_policy_yields_empty_documents() -> None:
    with mock_aws():
        iam = boto3.client("iam")
        iam.create_user(UserName="noinline")
        listing = await aws_iam_list_identities()

    user = next(u for u in listing.users if u.name == "noinline")
    assert user.inline_policy_names == ()
    assert user.inline_policies == ()
