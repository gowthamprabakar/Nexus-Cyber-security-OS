"""Tests for `identity.tools.aws_iam`.

`aws_iam_list_identities` is exercised against moto (which implements the
listing operations faithfully). `aws_iam_simulate_principal_policy` uses
a monkey-patched `boto3.Session` because moto raises NotImplementedError
on `simulate_principal_policy`; the wrapper's contract is "split actions
into ≤ 50-action batches and yield one decision per (action, resource)",
which we verify by capturing the calls made to a fake IAM client.

Async tests use the `with mock_aws():` context-manager form per the F.3
lesson (the `@mock_aws` decorator clobbers coroutines).
"""

from __future__ import annotations

from typing import Any

import boto3
import pytest
from identity.tools import aws_iam as aws_iam_mod
from identity.tools.aws_iam import (
    IamGroup,
    IamListingError,
    IamRole,
    IamUser,
    IdentityListing,
    SimulationDecision,
    aws_iam_list_identities,
    aws_iam_simulate_principal_policy,
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


# ====================== aws_iam_simulate_principal_policy =================


class _FakeIamClient:
    """Stub IAM client recording simulate_principal_policy calls.

    `decisions_by_action` maps an action name to its EvalDecision; unknown
    actions default to ``"implicitDeny"`` (matches IAM's behaviour).
    """

    def __init__(self, decisions_by_action: dict[str, str] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._decisions = decisions_by_action or {}

    def simulate_principal_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        actions = list(kwargs["ActionNames"])
        resources = list(kwargs.get("ResourceArns") or ["*"])
        results = []
        for action in actions:
            decision = self._decisions.get(action, "implicitDeny")
            for resource in resources:
                results.append(
                    {
                        "EvalActionName": action,
                        "EvalResourceName": resource,
                        "EvalDecision": decision,
                        "MatchedStatements": (
                            [{"SourcePolicyId": "test-policy"}] if decision == "allowed" else []
                        ),
                    }
                )
        return {"EvaluationResults": results}


class _FakeSession:
    """Drop-in for boto3.Session that returns a fixed IAM client."""

    def __init__(self, fake_client: _FakeIamClient, **_: Any) -> None:
        self._client = fake_client

    def client(self, name: str) -> _FakeIamClient:
        assert name == "iam", f"unexpected client name: {name}"
        return self._client


def _patch_session(monkeypatch: pytest.MonkeyPatch, fake: _FakeIamClient) -> None:
    def _factory(**kwargs: Any) -> _FakeSession:
        return _FakeSession(fake, **kwargs)

    monkeypatch.setattr(aws_iam_mod.boto3, "Session", _factory)


PRINCIPAL = "arn:aws:iam::123456789012:user/alice"


@pytest.mark.asyncio
async def test_simulate_returns_one_decision_per_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeIamClient({"s3:GetObject": "allowed", "ec2:TerminateInstances": "explicitDeny"})
    _patch_session(monkeypatch, fake)

    decisions = await aws_iam_simulate_principal_policy(
        principal_arn=PRINCIPAL,
        actions=["s3:GetObject", "ec2:TerminateInstances", "iam:CreateUser"],
    )

    assert len(decisions) == 3
    by_action = {d.action: d for d in decisions}
    assert by_action["s3:GetObject"].decision == "allowed"
    assert by_action["ec2:TerminateInstances"].decision == "explicitDeny"
    assert by_action["iam:CreateUser"].decision == "implicitDeny"
    assert all(d.principal_arn == PRINCIPAL for d in decisions)


@pytest.mark.asyncio
async def test_simulate_batches_actions_into_chunks_of_50(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """75 actions must split into 50 + 25 across two API calls."""
    fake = _FakeIamClient()
    _patch_session(monkeypatch, fake)
    actions = [f"svc:Action{i:03d}" for i in range(75)]

    decisions = await aws_iam_simulate_principal_policy(principal_arn=PRINCIPAL, actions=actions)

    assert len(fake.calls) == 2
    assert len(fake.calls[0]["ActionNames"]) == 50
    assert len(fake.calls[1]["ActionNames"]) == 25
    assert len(decisions) == 75
    assert {d.action for d in decisions} == set(actions)


@pytest.mark.asyncio
async def test_simulate_yields_decision_per_action_and_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """2 actions x 3 resources = 6 decision rows."""
    fake = _FakeIamClient({"s3:GetObject": "allowed"})
    _patch_session(monkeypatch, fake)
    resources = (
        "arn:aws:s3:::bucket-a/*",
        "arn:aws:s3:::bucket-b/*",
        "arn:aws:s3:::bucket-c/*",
    )

    decisions = await aws_iam_simulate_principal_policy(
        principal_arn=PRINCIPAL,
        actions=["s3:GetObject", "s3:PutObject"],
        resources=resources,
    )

    assert len(decisions) == 6
    triples = {(d.action, d.resource, d.decision) for d in decisions}
    for resource in resources:
        assert ("s3:GetObject", resource, "allowed") in triples
        assert ("s3:PutObject", resource, "implicitDeny") in triples


@pytest.mark.asyncio
async def test_simulate_captures_matched_statement_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeIamClient({"s3:GetObject": "allowed"})
    _patch_session(monkeypatch, fake)

    decisions = await aws_iam_simulate_principal_policy(
        principal_arn=PRINCIPAL, actions=["s3:GetObject"]
    )

    assert decisions[0].matched_statement_ids == ("test-policy",)


@pytest.mark.asyncio
async def test_simulate_passes_principal_arn_to_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeIamClient()
    _patch_session(monkeypatch, fake)

    await aws_iam_simulate_principal_policy(principal_arn=PRINCIPAL, actions=["s3:GetObject"])

    assert fake.calls[0]["PolicySourceArn"] == PRINCIPAL


@pytest.mark.asyncio
async def test_simulate_empty_actions_returns_empty_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeIamClient()
    _patch_session(monkeypatch, fake)

    decisions = await aws_iam_simulate_principal_policy(principal_arn=PRINCIPAL, actions=[])

    assert decisions == ()
    assert fake.calls == []


@pytest.mark.asyncio
async def test_simulate_wraps_boto_error_as_iam_listing_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _BoomClient(_FakeIamClient):
        def simulate_principal_policy(self, **kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("boto blew up")

    fake = _BoomClient()
    _patch_session(monkeypatch, fake)

    with pytest.raises(IamListingError):
        await aws_iam_simulate_principal_policy(principal_arn=PRINCIPAL, actions=["s3:GetObject"])


def test_simulation_decision_is_frozen() -> None:
    import dataclasses

    decision = SimulationDecision(
        principal_arn=PRINCIPAL,
        action="s3:GetObject",
        resource="*",
        decision="allowed",
    )
    assert dataclasses.is_dataclass(decision)
    with pytest.raises(dataclasses.FrozenInstanceError):
        decision.action = "mutated"  # type: ignore[misc]
