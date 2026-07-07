"""Unit tests for the aws_logging reader (defense-evasion enrichment — Cycle 8 Task 1).

Uses moto in-process mocks for CloudTrail (get_trail_status/IsLogging) and GuardDuty
(list_detectors/get_detector) — both verified as moto-supported.
"""

from __future__ import annotations

import boto3
import pytest
from cloud_posture.tools.aws_logging import AccountLoggingState, read_account_logging_state
from moto import mock_aws


@pytest.fixture
def aws_credentials(monkeypatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


# ---------------------------------------------------------------------------
# AccountLoggingState.logging_disabled property
# ---------------------------------------------------------------------------


def test_logging_disabled_both_on() -> None:
    s = AccountLoggingState(cloudtrail_logging=True, guardduty_enabled=True)
    assert s.logging_disabled is False


def test_logging_disabled_cloudtrail_off() -> None:
    s = AccountLoggingState(cloudtrail_logging=False, guardduty_enabled=True)
    assert s.logging_disabled is True


def test_logging_disabled_guardduty_off() -> None:
    s = AccountLoggingState(cloudtrail_logging=True, guardduty_enabled=False)
    assert s.logging_disabled is True


def test_logging_disabled_both_off() -> None:
    s = AccountLoggingState(cloudtrail_logging=False, guardduty_enabled=False)
    assert s.logging_disabled is True


# ---------------------------------------------------------------------------
# Reader: trail IsLogging=False → cloudtrail_logging=False → logging_disabled=True
# ---------------------------------------------------------------------------


def test_trail_not_logging_gives_disabled(aws_credentials) -> None:
    """A trail that exists but IsLogging=False → cloudtrail_logging=False → logging_disabled=True."""
    with mock_aws():
        ct = boto3.client("cloudtrail", region_name="us-east-1")
        s3 = boto3.client("s3", region_name="us-east-1")
        # Need an S3 bucket for the trail's S3BucketName
        s3.create_bucket(Bucket="test-trail-bucket")
        s3.put_bucket_policy(
            Bucket="test-trail-bucket",
            Policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::test-trail-bucket/*"}]}',
        )
        ct.create_trail(Name="test-trail", S3BucketName="test-trail-bucket")
        # Trail is created but NOT started — IsLogging=False
        gd = boto3.client("guardduty", region_name="us-east-1")
        state = read_account_logging_state(ct, gd)
        assert state.cloudtrail_logging is False
        assert state.logging_disabled is True


def test_trail_started_and_guardduty_enabled_gives_not_disabled(aws_credentials) -> None:
    """A started trail + an enabled GuardDuty detector → logging_disabled=False."""
    with mock_aws():
        ct = boto3.client("cloudtrail", region_name="us-east-1")
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-trail-bucket2")
        s3.put_bucket_policy(
            Bucket="test-trail-bucket2",
            Policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::test-trail-bucket2/*"}]}',
        )
        ct.create_trail(Name="active-trail", S3BucketName="test-trail-bucket2")
        ct.start_logging(Name="active-trail")

        gd = boto3.client("guardduty", region_name="us-east-1")
        # Create a GuardDuty detector — moto returns it as ENABLED by default
        gd.create_detector(Enable=True)

        state = read_account_logging_state(ct, gd)
        assert state.cloudtrail_logging is True
        assert state.guardduty_enabled is True
        assert state.logging_disabled is False


def test_no_trails_no_detectors_gives_disabled(aws_credentials) -> None:
    """Empty account (no trails, no detectors) → logging_disabled=True."""
    with mock_aws():
        ct = boto3.client("cloudtrail", region_name="us-east-1")
        gd = boto3.client("guardduty", region_name="us-east-1")
        state = read_account_logging_state(ct, gd)
        assert state.cloudtrail_logging is False
        assert state.guardduty_enabled is False
        assert state.logging_disabled is True
