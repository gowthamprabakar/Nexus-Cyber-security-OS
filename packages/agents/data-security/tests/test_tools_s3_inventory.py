"""Tests — ``data_security.tools.s3_inventory``.

Task 4. Verifies the S3 bucket-inventory reader:

- Happy-path parse (canonical ``{"buckets": [...]}`` shape, bare list).
- Missing file / not-a-file / malformed JSON → raises.
- Empty input → empty tuple.
- Per-bucket malformed → dropped silently (forgiving).
- Field defaults (PublicAccessBlock defaults to all-True).
- Edge cases on bucket name / account ID validation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from data_security.tools.s3_inventory import (
    BucketAcl,
    BucketEncryption,
    BucketInventory,
    PublicAccessBlock,
    S3InventoryReaderError,
    read_s3_inventory,
)


def _write_json(tmp_path: Path, content: object) -> Path:
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(content), encoding="utf-8")
    return path


def _well_formed_bucket(name: str = "corp-data-lake", **overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "name": name,
        "region": "us-east-1",
        "account_id": "123456789012",
        "acl": {
            "grants_all_users": [],
            "grants_authenticated_users": [],
        },
        "public_access_block": {
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": True,
            "restrict_public_buckets": True,
        },
        "encryption": {
            "algorithm": "AES256",
            "kms_master_key_id": None,
        },
        "policy_json": None,
        "tags": {},
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Happy-path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reads_canonical_buckets_shape(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path, {"buckets": [_well_formed_bucket("alpha"), _well_formed_bucket("beta")]}
    )
    result = await read_s3_inventory(path=path)
    assert len(result) == 2
    assert {b.name for b in result} == {"alpha", "beta"}


@pytest.mark.asyncio
async def test_reads_bare_list_shape(tmp_path: Path) -> None:
    """Bare top-level list is accepted (no ``{"buckets": [...]}`` wrapper)."""
    path = _write_json(tmp_path, [_well_formed_bucket("solo")])
    result = await read_s3_inventory(path=path)
    assert len(result) == 1
    assert result[0].name == "solo"


@pytest.mark.asyncio
async def test_empty_buckets_returns_empty_tuple(tmp_path: Path) -> None:
    path = _write_json(tmp_path, {"buckets": []})
    result = await read_s3_inventory(path=path)
    assert result == ()


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(S3InventoryReaderError, match="not found"):
        await read_s3_inventory(path=tmp_path / "missing.json")


@pytest.mark.asyncio
async def test_directory_path_raises(tmp_path: Path) -> None:
    """Passing a directory (not a file) raises with a clear message."""
    with pytest.raises(S3InventoryReaderError, match="not a file"):
        await read_s3_inventory(path=tmp_path)


@pytest.mark.asyncio
async def test_malformed_json_raises(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(S3InventoryReaderError, match="malformed"):
        await read_s3_inventory(path=path)


# ---------------------------------------------------------------------------
# Forgiving parse — bad buckets dropped
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_drops_malformed_bucket_keeps_good_ones(tmp_path: Path) -> None:
    """A single malformed bucket entry is dropped; the rest of the file
    still parses. Mirrors F.3 / multi-cloud-posture forgiving pattern.
    """
    malformed = {"name": "", "region": "us-east-1"}  # name min_length=1 → invalid
    path = _write_json(
        tmp_path,
        {"buckets": [_well_formed_bucket("good-1"), malformed, _well_formed_bucket("good-2")]},
    )
    result = await read_s3_inventory(path=path)
    assert len(result) == 2
    assert {b.name for b in result} == {"good-1", "good-2"}


@pytest.mark.asyncio
async def test_non_dict_entries_ignored(tmp_path: Path) -> None:
    """Non-dict entries in the list are ignored at the extraction layer."""
    path = _write_json(
        tmp_path,
        {"buckets": [_well_formed_bucket("good"), "not-a-dict", 42, None]},
    )
    result = await read_s3_inventory(path=path)
    assert len(result) == 1
    assert result[0].name == "good"


@pytest.mark.asyncio
async def test_top_level_neither_dict_nor_list_returns_empty(tmp_path: Path) -> None:
    """Non-dict, non-list top-level JSON parses to empty (defensive)."""
    path = _write_json(tmp_path, 42)
    result = await read_s3_inventory(path=path)
    assert result == ()


# ---------------------------------------------------------------------------
# Field defaults + validation
# ---------------------------------------------------------------------------


def test_public_access_block_defaults_all_true() -> None:
    pab = PublicAccessBlock()
    assert pab.block_public_acls
    assert pab.ignore_public_acls
    assert pab.block_public_policy
    assert pab.restrict_public_buckets


def test_bucket_acl_defaults_empty_lists() -> None:
    acl = BucketAcl()
    assert acl.grants_all_users == []
    assert acl.grants_authenticated_users == []


def test_bucket_encryption_accepts_known_algorithms() -> None:
    for alg in ("NONE", "AES256", "aws:kms", "aws:kms:dsse"):
        enc = BucketEncryption(algorithm=alg)
        assert enc.algorithm == alg


def test_bucket_encryption_rejects_unknown_algorithm() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        BucketEncryption(algorithm="rot13")


def test_bucket_inventory_arn_property() -> None:
    bucket = BucketInventory.model_validate(_well_formed_bucket("my-bucket"))
    assert bucket.arn == "arn:aws:s3:::my-bucket"


def test_bucket_inventory_rejects_short_name() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        BucketInventory.model_validate({**_well_formed_bucket(), "name": ""})


def test_bucket_inventory_rejects_oversized_name() -> None:
    """S3 bucket names are 63 chars max."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        BucketInventory.model_validate({**_well_formed_bucket(), "name": "a" * 64})


def test_bucket_inventory_rejects_bad_account_id() -> None:
    """Account IDs are exactly 12 digits."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        BucketInventory.model_validate({**_well_formed_bucket(), "account_id": "abc"})
    with pytest.raises(ValidationError):
        BucketInventory.model_validate({**_well_formed_bucket(), "account_id": "12345"})


@pytest.mark.asyncio
async def test_round_trip_preserves_all_fields(tmp_path: Path) -> None:
    """Round-trip a fully-populated bucket through the reader."""
    bucket_dict = _well_formed_bucket(
        "complex-bucket",
        public_access_block={
            "block_public_acls": False,
            "ignore_public_acls": False,
            "block_public_policy": False,
            "restrict_public_buckets": False,
        },
        acl={
            "grants_all_users": ["READ"],
            "grants_authenticated_users": ["READ", "WRITE"],
        },
        encryption={"algorithm": "aws:kms", "kms_master_key_id": "alias/data-key"},
        policy_json='{"Version":"2012-10-17","Statement":[]}',
        tags={"Sensitivity": "Restricted", "Environment": "prod"},
    )
    path = _write_json(tmp_path, {"buckets": [bucket_dict]})
    result = await read_s3_inventory(path=path)
    assert len(result) == 1
    bucket = result[0]
    assert bucket.name == "complex-bucket"
    assert bucket.public_access_block.block_public_acls is False
    assert bucket.acl.grants_all_users == ["READ"]
    assert bucket.acl.grants_authenticated_users == ["READ", "WRITE"]
    assert bucket.encryption.algorithm == "aws:kms"
    assert bucket.encryption.kms_master_key_id == "alias/data-key"
    assert bucket.policy_json == '{"Version":"2012-10-17","Statement":[]}'
    assert bucket.tags["Sensitivity"] == "Restricted"
    assert bucket.tags["Environment"] == "prod"
