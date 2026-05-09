"""Tests for AWS IAM analyzer (async).

Note: moto's `@mock_aws` decorator does not preserve coroutine functions.
We use it as a context manager inside async tests instead (per ADR-005).
"""

import boto3
import pytest
from cloud_posture.tools.aws_iam import (
    list_admin_policies,
    list_users_without_mfa,
)
from moto import mock_aws

_FAKE_PASSWORD = "P@ssw0rd!Strong!"  # noqa: S105 — moto fixture, not a real secret

_TOO_BROAD_DOC = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
)
_SCOPED_DOC = (
    '{"Version":"2012-10-17",'
    '"Statement":[{"Effect":"Allow",'
    '"Action":"s3:GetObject","Resource":"arn:aws:s3:::x/*"}]}'
)


@pytest.fixture
def aws_credentials(monkeypatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.mark.asyncio
async def test_list_users_without_mfa(aws_credentials) -> None:
    with mock_aws():
        iam = boto3.client("iam")
        iam.create_user(UserName="alice")
        iam.create_user(UserName="bob")
        iam.create_login_profile(UserName="alice", Password=_FAKE_PASSWORD)
        iam.create_login_profile(UserName="bob", Password=_FAKE_PASSWORD)
        device = iam.create_virtual_mfa_device(VirtualMFADeviceName="alice")
        iam.enable_mfa_device(
            UserName="alice",
            SerialNumber=device["VirtualMFADevice"]["SerialNumber"],
            AuthenticationCode1="123456",
            AuthenticationCode2="654321",
        )

        result = await list_users_without_mfa()
        assert result == ["bob"]


@pytest.mark.asyncio
async def test_list_users_without_mfa_skips_users_without_console_password(
    aws_credentials,
) -> None:
    """Users without a login profile (programmatic-only) are excluded."""
    with mock_aws():
        iam = boto3.client("iam")
        iam.create_user(UserName="programmatic-only")
        iam.create_user(UserName="console-no-mfa")
        iam.create_login_profile(UserName="console-no-mfa", Password=_FAKE_PASSWORD)

        result = await list_users_without_mfa()
        assert result == ["console-no-mfa"]


@pytest.mark.asyncio
async def test_list_admin_policies_detects_star_action_and_resource(
    aws_credentials,
) -> None:
    with mock_aws():
        iam = boto3.client("iam")
        iam.create_policy(PolicyName="TooBroad", PolicyDocument=_TOO_BROAD_DOC)
        iam.create_policy(PolicyName="Scoped", PolicyDocument=_SCOPED_DOC)

        result = await list_admin_policies()
        names = {p["policy_name"] for p in result}
        assert "TooBroad" in names
        assert "Scoped" not in names


@pytest.mark.asyncio
async def test_list_admin_policies_handles_single_statement_dict(
    aws_credentials,
) -> None:
    """A policy whose Statement is a single dict (not a list) must still parse."""
    single_stmt_doc = (
        '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}'
    )
    with mock_aws():
        iam = boto3.client("iam")
        iam.create_policy(PolicyName="SingleStmt", PolicyDocument=single_stmt_doc)

        result = await list_admin_policies()
        assert any(p["policy_name"] == "SingleStmt" for p in result)


@pytest.mark.asyncio
async def test_list_admin_policies_empty_when_only_aws_managed(
    aws_credentials,
) -> None:
    """Scope=Local must exclude AWS-managed policies."""
    with mock_aws():
        result = await list_admin_policies()
        assert result == []
