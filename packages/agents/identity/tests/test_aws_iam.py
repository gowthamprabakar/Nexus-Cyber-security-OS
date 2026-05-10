"""Tests for `identity.tools.aws_iam.aws_iam_list_identities`.

Uses moto to seed an in-memory IAM service. Async tests use the
`with mock_aws():` context-manager form per the F.3 lesson (the
`@mock_aws` decorator clobbers coroutines).
"""

from __future__ import annotations

import boto3
import pytest
from identity.tools.aws_iam import (
    IamGroup,
    IamListingError,
    IamRole,
    IamUser,
    IdentityListing,
    aws_iam_list_identities,
)
from moto import mock_aws


def _seed_account(iam: object) -> tuple[str, str, str]:
    """Seed users + roles + groups + customer-managed policies. Returns the policy ARNs.

    Moto does not preload AWS-managed policies, so we create customer-managed
    equivalents and use those ARNs instead. This is how real test envs work
    too (a customer can't trust AWS-managed policy ARNs to be there in moto).
    """
    admin_policy = iam.create_policy(  # type: ignore[attr-defined]
        PolicyName="TestAdministratorAccess",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
    )["Policy"]["Arn"]
    iam_full_policy = iam.create_policy(  # type: ignore[attr-defined]
        PolicyName="TestIAMFullAccess",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}',
    )["Policy"]["Arn"]
    lambda_basic_policy = iam.create_policy(  # type: ignore[attr-defined]
        PolicyName="TestAWSLambdaBasicExecutionRole",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:*"],"Resource":"*"}]}',
    )["Policy"]["Arn"]

    iam.create_user(UserName="alice")  # type: ignore[attr-defined]
    iam.create_user(UserName="bob")  # type: ignore[attr-defined]

    iam.create_group(GroupName="admins")  # type: ignore[attr-defined]
    iam.add_user_to_group(GroupName="admins", UserName="alice")  # type: ignore[attr-defined]

    iam.attach_user_policy(UserName="alice", PolicyArn=admin_policy)  # type: ignore[attr-defined]
    iam.attach_group_policy(GroupName="admins", PolicyArn=iam_full_policy)  # type: ignore[attr-defined]

    iam.put_user_policy(  # type: ignore[attr-defined]
        UserName="bob",
        PolicyName="bob-inline",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
    )

    iam.create_role(  # type: ignore[attr-defined]
        RoleName="LambdaExecutionRole",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}',
    )
    iam.attach_role_policy(  # type: ignore[attr-defined]
        RoleName="LambdaExecutionRole",
        PolicyArn=lambda_basic_policy,
    )

    return admin_policy, iam_full_policy, lambda_basic_policy


# ---------------------------- happy path ---------------------------------


@pytest.mark.asyncio
async def test_returns_users_roles_groups() -> None:
    with mock_aws():
        _seed_account(boto3.client("iam"))
        listing = await aws_iam_list_identities()

    assert isinstance(listing, IdentityListing)
    assert {u.name for u in listing.users} == {"alice", "bob"}
    assert {g.name for g in listing.groups} == {"admins"}
    assert {r.name for r in listing.roles} == {"LambdaExecutionRole"}


@pytest.mark.asyncio
async def test_user_attached_managed_policies_captured() -> None:
    with mock_aws():
        admin_arn, _, _ = _seed_account(boto3.client("iam"))
        listing = await aws_iam_list_identities()

    alice = next(u for u in listing.users if u.name == "alice")
    assert admin_arn in alice.attached_policy_arns


@pytest.mark.asyncio
async def test_user_inline_policies_captured() -> None:
    with mock_aws():
        _seed_account(boto3.client("iam"))
        listing = await aws_iam_list_identities()

    bob = next(u for u in listing.users if u.name == "bob")
    assert "bob-inline" in bob.inline_policy_names


@pytest.mark.asyncio
async def test_user_group_membership_captured() -> None:
    with mock_aws():
        _seed_account(boto3.client("iam"))
        listing = await aws_iam_list_identities()

    alice = next(u for u in listing.users if u.name == "alice")
    assert "admins" in alice.group_memberships


@pytest.mark.asyncio
async def test_role_assume_policy_captured() -> None:
    with mock_aws():
        _seed_account(boto3.client("iam"))
        listing = await aws_iam_list_identities()

    role = next(r for r in listing.roles if r.name == "LambdaExecutionRole")
    assert (
        role.assume_role_policy_document["Statement"][0]["Principal"]["Service"]
        == "lambda.amazonaws.com"
    )


@pytest.mark.asyncio
async def test_group_member_users_captured() -> None:
    with mock_aws():
        _seed_account(boto3.client("iam"))
        listing = await aws_iam_list_identities()

    admins = next(g for g in listing.groups if g.name == "admins")
    assert "alice" in admins.member_user_names


@pytest.mark.asyncio
async def test_group_attached_policies_captured() -> None:
    with mock_aws():
        _, iam_full_arn, _ = _seed_account(boto3.client("iam"))
        listing = await aws_iam_list_identities()

    admins = next(g for g in listing.groups if g.name == "admins")
    assert iam_full_arn in admins.attached_policy_arns


# ---------------------------- empty account ------------------------------


@pytest.mark.asyncio
async def test_empty_account_returns_empty_listing() -> None:
    with mock_aws():
        # No seeding — fresh account.
        listing = await aws_iam_list_identities()

    assert listing.users == ()
    assert listing.roles == ()
    assert listing.groups == ()


# ---------------------------- pagination ---------------------------------


@pytest.mark.asyncio
async def test_pagination_across_many_users() -> None:
    """Seed 25 users; the wrapper must capture all of them via the paginator."""
    with mock_aws():
        iam = boto3.client("iam")
        for i in range(25):
            iam.create_user(UserName=f"user{i:03d}")
        listing = await aws_iam_list_identities()

    assert len(listing.users) == 25
    assert {u.name for u in listing.users} == {f"user{i:03d}" for i in range(25)}


# ---------------------------- error paths --------------------------------


@pytest.mark.asyncio
async def test_invalid_profile_raises_iam_listing_error() -> None:
    """An unknown AWS profile should be wrapped as IamListingError, not bubble through."""
    with pytest.raises(IamListingError):
        await aws_iam_list_identities(profile="profile-that-does-not-exist-xyz")


# ---------------------------- typed dataclass shape ---------------------


def test_dataclasses_are_frozen() -> None:
    """All four dataclasses must be frozen so the resolver can hash them."""
    import dataclasses
    from datetime import UTC, datetime

    user = IamUser(
        arn="arn:aws:iam::1:user/x",
        name="x",
        user_id="AID",
        create_date=datetime.now(UTC),
        last_used_at=None,
    )
    role = IamRole(
        arn="arn:aws:iam::1:role/r",
        name="r",
        role_id="ARO",
        create_date=datetime.now(UTC),
        last_used_at=None,
        assume_role_policy_document={},
    )
    group = IamGroup(
        arn="arn:aws:iam::1:group/g",
        name="g",
        group_id="AGP",
        create_date=datetime.now(UTC),
    )
    for obj in (user, role, group):
        assert dataclasses.is_dataclass(obj)
        with pytest.raises(dataclasses.FrozenInstanceError):
            obj.name = "mutated"  # type: ignore[misc]
