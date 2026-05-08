"""Tests for AWS S3 describe tools using moto in-memory mocks."""

import boto3
import pytest
from botocore.exceptions import ClientError
from cloud_posture.tools.aws_s3 import describe_bucket, list_buckets
from moto import mock_aws


@pytest.fixture
def aws_credentials(monkeypatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@mock_aws
def test_list_buckets_empty(aws_credentials) -> None:
    result = list_buckets(region="us-east-1")
    assert result == []


@mock_aws
def test_list_buckets_returns_names(aws_credentials) -> None:
    client = boto3.client("s3", region_name="us-east-1")
    client.create_bucket(Bucket="alpha")
    client.create_bucket(Bucket="beta")
    result = list_buckets(region="us-east-1")
    assert sorted(result) == ["alpha", "beta"]


@mock_aws
def test_describe_bucket_basic(aws_credentials) -> None:
    client = boto3.client("s3", region_name="us-east-1")
    client.create_bucket(Bucket="alpha")
    info = describe_bucket(bucket="alpha", region="us-east-1")
    assert info["bucket"] == "alpha"
    assert info["region"] == "us-east-1"
    assert "encryption" in info
    assert "policy" in info
    assert "acl" in info


@mock_aws
def test_describe_bucket_missing_raises(aws_credentials) -> None:
    with pytest.raises(ClientError):
        describe_bucket(bucket="does-not-exist", region="us-east-1")
