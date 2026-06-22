"""Unit tests for the shared canonical resource-ARN builders."""

from charter.canonical import s3_bucket_arn


def test_s3_bucket_arn_is_canonical():
    assert s3_bucket_arn("acme-pii") == "arn:aws:s3:::acme-pii"
