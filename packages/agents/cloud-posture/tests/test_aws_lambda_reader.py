"""Unit tests — LambdaWorkload reader via moto in-process mocks.

Cycle 6: serverless Lambda exposure archetype.

Three cases:
1. Function URL with AuthType=NONE → is_public=True
2. Resource policy with wildcard principal Allow → is_public=True
3. Function URL with AuthType=AWS_IAM (IAM-auth) → is_public=False (private)

moto supports create_function, create_function_url_config, add_permission
(resource policy) for Lambda.
"""

from __future__ import annotations

import json

import boto3
import pytest
from cloud_posture.tools.aws_lambda import LambdaWorkload, read_lambda_workloads
from moto import mock_aws

_REGION = "us-east-1"
_ROLE_ARN = "arn:aws:iam::123456789012:role/lambda-exec-role"

# Minimal Lambda zip (empty) — moto accepts any non-empty bytes here
_DUMMY_ZIP = b"PK\x05\x06" + b"\x00" * 18


@pytest.fixture()
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", _REGION)


def _lambda_client() -> object:
    return boto3.client("lambda", region_name=_REGION)


def _iam_client() -> object:
    return boto3.client("iam", region_name=_REGION)


def _create_role(iam: object, name: str = "lambda-exec-role") -> str:
    """Create a minimal IAM role and return its ARN."""
    assume_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    resp = iam.create_role(  # type: ignore[attr-defined]
        RoleName=name,
        AssumeRolePolicyDocument=assume_policy,
    )
    return resp["Role"]["Arn"]


def _create_function(lam: object, name: str, role_arn: str) -> str:
    """Create a minimal Lambda function and return its ARN."""
    resp = lam.create_function(  # type: ignore[attr-defined]
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="handler.lambda_handler",
        Code={"ZipFile": _DUMMY_ZIP},
    )
    return resp["FunctionArn"]


# ---------------------------------------------------------------------------
# Test 1: Function URL with AuthType=NONE → is_public=True
# ---------------------------------------------------------------------------


def test_lambda_url_auth_none_is_public(aws_credentials: None) -> None:
    """A function with a public URL (AuthType=NONE) is flagged is_public=True."""
    with mock_aws():
        lam = _lambda_client()
        iam = _iam_client()
        role_arn = _create_role(iam)
        fn_arn = _create_function(lam, "public-url-fn", role_arn)
        # Create a public function URL
        lam.create_function_url_config(  # type: ignore[attr-defined]
            FunctionName="public-url-fn",
            AuthType="NONE",
        )

        workloads = read_lambda_workloads(lam, iam)

    assert len(workloads) == 1, f"expected 1 workload, got {workloads}"
    w = workloads[0]
    assert isinstance(w, LambdaWorkload)
    assert w.function_arn == fn_arn
    assert w.is_public is True, f"expected is_public=True for AuthType=NONE, got {w.is_public}"
    assert w.role_arn == role_arn


# ---------------------------------------------------------------------------
# Test 2: Resource policy with wildcard principal → is_public=True
# ---------------------------------------------------------------------------


def test_lambda_wildcard_resource_policy_is_public(aws_credentials: None) -> None:
    """A function with a wildcard-Allow resource policy is flagged is_public=True."""
    with mock_aws():
        lam = _lambda_client()
        iam = _iam_client()
        role_arn = _create_role(iam)
        fn_arn = _create_function(lam, "policy-public-fn", role_arn)
        # Add a public resource policy (no function URL)
        lam.add_permission(  # type: ignore[attr-defined]
            FunctionName="policy-public-fn",
            StatementId="public-invoke",
            Action="lambda:InvokeFunction",
            Principal="*",
        )

        workloads = read_lambda_workloads(lam, iam)

    assert len(workloads) == 1, f"expected 1 workload, got {workloads}"
    w = workloads[0]
    assert w.function_arn == fn_arn
    assert w.is_public is True, (
        f"expected is_public=True for wildcard resource policy, got {w.is_public}"
    )
    assert w.role_arn == role_arn


# ---------------------------------------------------------------------------
# Test 3: Function URL with AuthType=AWS_IAM → is_public=False
# ---------------------------------------------------------------------------


def test_lambda_url_iam_auth_is_private(aws_credentials: None) -> None:
    """A function with IAM-authenticated URL (AuthType=AWS_IAM) is flagged is_public=False."""
    with mock_aws():
        lam = _lambda_client()
        iam = _iam_client()
        role_arn = _create_role(iam)
        fn_arn = _create_function(lam, "private-iam-fn", role_arn)
        # Create a URL with IAM auth — NOT public
        lam.create_function_url_config(  # type: ignore[attr-defined]
            FunctionName="private-iam-fn",
            AuthType="AWS_IAM",
        )

        workloads = read_lambda_workloads(lam, iam)

    assert len(workloads) == 1, f"expected 1 workload, got {workloads}"
    w = workloads[0]
    assert w.function_arn == fn_arn
    assert w.is_public is False, f"expected is_public=False for AuthType=AWS_IAM, got {w.is_public}"
    assert w.role_arn == role_arn
