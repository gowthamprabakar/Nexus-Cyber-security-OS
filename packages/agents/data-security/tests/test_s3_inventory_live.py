"""data-security v0.2 Task 2 — live AWS S3 bucket inventory tests (injected client)."""

from __future__ import annotations

from typing import Any

from data_security.tools.s3_inventory import BucketInventory
from data_security.tools.s3_inventory_live import S3LiveInventoryReader

_ACCT = "111122223333"


class _FakeS3:
    """A minimal fake S3 client returning canned per-bucket responses."""

    def __init__(self, *, buckets: list[str], public: bool = False, encrypted: bool = True) -> None:
        self._buckets = buckets
        self._public = public
        self._encrypted = encrypted
        self.calls: list[str] = []

    def list_buckets(self) -> dict[str, Any]:
        return {"Buckets": [{"Name": b} for b in self._buckets]}

    def get_bucket_location(self, *, Bucket: str) -> dict[str, Any]:
        return {"LocationConstraint": "eu-west-1"}

    def get_bucket_acl(self, *, Bucket: str) -> dict[str, Any]:
        self.calls.append(f"acl:{Bucket}")
        if self._public:
            return {
                "Grants": [
                    {
                        "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                        "Permission": "READ",
                    }
                ]
            }
        return {"Grants": []}

    def get_public_access_block(self, *, Bucket: str) -> dict[str, Any]:
        flag = not self._public
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": flag,
                "IgnorePublicAcls": flag,
                "BlockPublicPolicy": flag,
                "RestrictPublicBuckets": flag,
            }
        }

    def get_bucket_encryption(self, *, Bucket: str) -> dict[str, Any]:
        if not self._encrypted:
            raise RuntimeError("ServerSideEncryptionConfigurationNotFoundError")
        return {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }

    def get_bucket_policy(self, *, Bucket: str) -> dict[str, Any]:
        raise RuntimeError("NoSuchBucketPolicy")

    def get_bucket_tagging(self, *, Bucket: str) -> dict[str, Any]:
        return {"TagSet": [{"Key": "Sensitivity", "Value": "high"}]}


def test_reads_buckets() -> None:
    reader = S3LiveInventoryReader(_FakeS3(buckets=["data-a", "data-b"]), account_id=_ACCT)
    out = reader.read()
    assert len(out) == 2 and all(isinstance(b, BucketInventory) for b in out)
    assert {b.name for b in out} == {"data-a", "data-b"}


def test_region_and_account() -> None:
    [b] = S3LiveInventoryReader(_FakeS3(buckets=["x"]), account_id=_ACCT).read()
    assert b.region == "eu-west-1" and b.account_id == _ACCT


def test_public_bucket_acl_grants() -> None:
    [b] = S3LiveInventoryReader(_FakeS3(buckets=["x"], public=True), account_id=_ACCT).read()
    assert b.acl.grants_all_users == ["READ"]
    assert b.public_access_block.block_public_acls is False


def test_private_bucket_no_grants() -> None:
    [b] = S3LiveInventoryReader(_FakeS3(buckets=["x"]), account_id=_ACCT).read()
    assert b.acl.grants_all_users == []
    assert b.public_access_block.block_public_acls is True


def test_encryption_present() -> None:
    [b] = S3LiveInventoryReader(_FakeS3(buckets=["x"]), account_id=_ACCT).read()
    assert b.encryption.algorithm == "AES256"


def test_encryption_absent_is_none() -> None:
    [b] = S3LiveInventoryReader(_FakeS3(buckets=["x"], encrypted=False), account_id=_ACCT).read()
    assert b.encryption.algorithm == "NONE"


def test_tags_collected() -> None:
    [b] = S3LiveInventoryReader(_FakeS3(buckets=["x"]), account_id=_ACCT).read()
    assert b.tags.get("Sensitivity") == "high"


def test_missing_policy_is_none() -> None:
    [b] = S3LiveInventoryReader(_FakeS3(buckets=["x"]), account_id=_ACCT).read()
    assert b.policy_json is None  # NoSuchBucketPolicy tolerated


def test_byte_identical_with_offline(tmp_path: Any) -> None:
    import json

    from data_security.tools.s3_inventory import _read_sync

    live = S3LiveInventoryReader(
        _FakeS3(buckets=["x"], public=True, encrypted=False), account_id=_ACCT
    ).read()
    # The same logical bucket as an offline snapshot record.
    record = live[0].model_dump()
    p = tmp_path / "inv.json"
    p.write_text(json.dumps({"buckets": [record]}), encoding="utf-8")
    offline = _read_sync(p)
    assert offline[0].model_dump() == record


def test_no_name_bucket_skipped() -> None:
    class _Bad(_FakeS3):
        def list_buckets(self) -> dict[str, Any]:
            return {"Buckets": [{"NoName": "x"}, {"Name": "good"}]}

    out = S3LiveInventoryReader(_Bad(buckets=[]), account_id=_ACCT).read()
    assert [b.name for b in out] == ["good"]
