"""Unit tests — Ec2Workload.imdsv1_enabled flag via moto in-process mocks.

Cycle 5 Task 1: IMDS/SSRF → credential-theft archetype.

The new ``imdsv1_enabled`` field on :class:`Ec2Workload` discriminates between
IMDSv1 (HttpTokens=optional → True, cred-stealable) and IMDSv2-only
(HttpTokens=required → False, safe).  moto returns MetadataOptions on
describe_instances, so the field is populated from the live path too.

Note: moto's ``@mock_aws`` decorator does not preserve coroutine functions.
We use it as a context manager inside sync (non-async) tests instead.
"""

from __future__ import annotations

import boto3
import pytest
from cloud_posture.tools.aws_ec2 import Ec2Workload, read_ec2_workloads
from moto import mock_aws


@pytest.fixture()
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


def _ec2_client(region: str = "us-east-1") -> object:
    return boto3.client("ec2", region_name=region)


def _iam_client() -> object:
    return boto3.client("iam", region_name="us-east-1")


def _launch_instance(
    ec2: object,
    *,
    public_ip: bool = False,
    http_tokens: str = "optional",
) -> str:
    """Launch one running EC2 instance and return its InstanceId.

    ``public_ip`` creates a security group that allows 0.0.0.0/0 ingress so
    ``_sg_allows_public`` marks it internet-exposed. ``http_tokens`` controls the
    MetadataOptions.HttpTokens value moto returns.
    """
    # Moto creates a default VPC + subnet; use them.
    ec2_obj = boto3.resource("ec2", region_name="us-east-1")  # type: ignore[attr-defined]
    sg = ec2_obj.create_security_group(GroupName="test-sg", Description="test")
    if public_ip:
        sg.authorize_ingress(
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        )
    instances = ec2_obj.create_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[sg.id],
        MetadataOptions={"HttpTokens": http_tokens},
    )
    return instances[0].id


def test_ec2_workload_dataclass_has_imdsv1_field(aws_credentials: None) -> None:
    """Ec2Workload has imdsv1_enabled with default False."""
    w = Ec2Workload(instance_arn="arn:aws:ec2:us-east-1:123:instance/i-abc", is_public=False)
    assert w.imdsv1_enabled is False


def test_read_ec2_workloads_imdsv1_optional_sets_true(aws_credentials: None) -> None:
    """HttpTokens=optional → imdsv1_enabled=True (the cred-stealable case)."""
    with mock_aws():
        ec2 = _ec2_client()
        iam = _iam_client()
        _launch_instance(ec2, public_ip=False, http_tokens="optional")
        workloads = read_ec2_workloads(ec2, iam, account_id="123456789012", region="us-east-1")
    assert len(workloads) == 1
    assert workloads[0].imdsv1_enabled is True


def test_read_ec2_workloads_imdsv1_required_sets_false(aws_credentials: None) -> None:
    """HttpTokens=required → imdsv1_enabled=False (the safe/IMDSv2-only case)."""
    with mock_aws():
        ec2 = _ec2_client()
        iam = _iam_client()
        _launch_instance(ec2, public_ip=False, http_tokens="required")
        workloads = read_ec2_workloads(ec2, iam, account_id="123456789012", region="us-east-1")
    assert len(workloads) == 1
    assert workloads[0].imdsv1_enabled is False
