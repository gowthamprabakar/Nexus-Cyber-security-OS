"""data-security v0.2 Task 4 — AWS S3 data residency tracking tests (WI-S10)."""

from __future__ import annotations

from data_security.residency.aws_s3 import (
    Jurisdiction,
    ResidencyRecord,
    classify_region,
    gdpr_in_scope,
    track_residency,
)
from data_security.tools.s3_inventory import BucketEncryption, BucketInventory


def _bucket(name: str, region: str) -> BucketInventory:
    return BucketInventory(
        name=name,
        region=region,
        account_id="111122223333",
        encryption=BucketEncryption(algorithm="AES256"),
    )


def test_classify_eu() -> None:
    assert classify_region("eu-west-1") == Jurisdiction.EU
    assert classify_region("eu-central-1") == Jurisdiction.EU


def test_classify_us() -> None:
    assert classify_region("us-east-1") == Jurisdiction.US
    assert classify_region("ca-central-1") == Jurisdiction.US


def test_classify_apac() -> None:
    assert classify_region("ap-southeast-2") == Jurisdiction.APAC


def test_classify_other() -> None:
    assert classify_region("sa-east-1") == Jurisdiction.OTHER


def test_track_residency() -> None:
    records = track_residency([_bucket("a", "eu-west-1"), _bucket("b", "us-east-1")])
    assert len(records) == 2
    by_bucket = {r.bucket: r.jurisdiction for r in records}
    assert by_bucket["a"] == Jurisdiction.EU and by_bucket["b"] == Jurisdiction.US


def test_gdpr_in_scope() -> None:
    [eu] = track_residency([_bucket("a", "eu-west-1")])
    [us] = track_residency([_bucket("b", "us-east-1")])
    assert gdpr_in_scope(eu) is True and gdpr_in_scope(us) is False


def test_record_is_metadata_only() -> None:
    # WI-S10: residency record carries bucket + region + jurisdiction ONLY — no content/keys.
    [r] = track_residency([_bucket("a", "eu-west-1")])
    assert set(r.to_metadata()) == {"bucket", "region", "jurisdiction"}
    fields = ResidencyRecord.__slots__
    assert set(fields) == {"bucket", "region", "jurisdiction"}
    assert not any("content" in f or "key" in f or "object" in f for f in fields)


def test_empty() -> None:
    assert track_residency([]) == ()
