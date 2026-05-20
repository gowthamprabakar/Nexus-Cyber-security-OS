"""``read_s3_inventory`` — filesystem ingest for S3 bucket inventory snapshots.

Reads an operator-staged JSON dump of AWS S3 bucket metadata and converts
each entry into a typed ``BucketInventory``. Per ADR-005 the filesystem
read happens on ``asyncio.to_thread``; the wrapper is ``async`` for
TaskGroup fan-out from the agent driver (Task 12).

**Operator workflow.** Per the D.5 v0.1 runbook, operators run:

.. code-block:: bash

    aws s3api list-buckets   # then per bucket:
    aws s3api get-bucket-acl --bucket <name>
    aws s3api get-public-access-block --bucket <name>
    aws s3api get-bucket-encryption --bucket <name>
    aws s3api get-bucket-policy --bucket <name>
    aws s3api get-bucket-tagging --bucket <name>

and stitch the results into a single ``buckets.json`` matching the
``{"buckets": [...]}`` shape this reader expects.

D.5 v0.2 replaces this with live boto3 calls behind the same async
wrapper signature.

**Forgiving** on malformed bucket entries — a single bad bucket is
dropped, not the whole file. Mirrors F.3 / multi-cloud-posture
patterns.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class S3InventoryReaderError(RuntimeError):
    """The S3 bucket inventory JSON feed could not be read."""


class BucketAcl(BaseModel):
    """Subset of the S3 bucket ACL shape that the detectors care about.

    The detectors (Tasks 5-8) only need to know whether the ACL grants
    ``READ`` / ``FULL_CONTROL`` to ``AllUsers`` or ``AuthenticatedUsers``;
    we capture the grant tuples here. Other ACL fields are dropped.
    """

    grants_all_users: list[str] = Field(default_factory=list)
    """Permission strings granted to ``http://acs.amazonaws.com/groups/global/AllUsers``."""

    grants_authenticated_users: list[str] = Field(default_factory=list)
    """Permission strings granted to
    ``http://acs.amazonaws.com/groups/global/AuthenticatedUsers``."""


class PublicAccessBlock(BaseModel):
    """The four S3 Block Public Access flags.

    When any flag is False, the bucket may be exposed via the
    corresponding policy / ACL pathway. ``s3_bucket_public`` detector
    flags a bucket as HIGH when any of these are False AND the ACL has
    a public grant.
    """

    block_public_acls: bool = True
    ignore_public_acls: bool = True
    block_public_policy: bool = True
    restrict_public_buckets: bool = True


class BucketEncryption(BaseModel):
    """Default server-side encryption configuration.

    ``algorithm == "NONE"`` indicates the bucket has no default SSE
    configured. ``s3_bucket_unencrypted`` detector flags MEDIUM at NONE.
    """

    algorithm: str = Field(pattern=r"^(NONE|AES256|aws:kms|aws:kms:dsse)$")
    kms_master_key_id: str | None = None


class BucketInventory(BaseModel):
    """One S3 bucket's posture, normalised for the detectors.

    All fields below are derived from the per-bucket AWS API responses
    stitched together by the operator before scan time. The shape is
    flat so detector logic stays readable.
    """

    name: str = Field(min_length=1, max_length=63)
    region: str = Field(min_length=1)
    account_id: str = Field(min_length=12, max_length=12, pattern=r"^\d{12}$")
    acl: BucketAcl = Field(default_factory=BucketAcl)
    public_access_block: PublicAccessBlock = Field(default_factory=PublicAccessBlock)
    encryption: BucketEncryption
    policy_json: str | None = None
    """Raw bucket-policy JSON (as returned by ``get-bucket-policy``), or
    None if no policy is attached. ``s3_oversharing_iam`` detector parses
    this. Kept as the original string so we don't lose ``Sid`` ordering
    or operator comments."""

    tags: dict[str, str] = Field(default_factory=dict)
    """Bucket-level tag map. ``s3_object_sensitive_in_untrusted_location``
    detector consults ``tags.get("Sensitivity")`` to decide whether a
    classifier-flagged object is in an untrusted bucket."""

    @property
    def arn(self) -> str:
        return f"arn:aws:s3:::{self.name}"


async def read_s3_inventory(*, path: Path) -> tuple[BucketInventory, ...]:
    """Read an S3 bucket inventory JSON dump and return the parsed buckets.

    Raises ``S3InventoryReaderError`` if the file is missing, not a file,
    or malformed JSON. Individual buckets that fail validation are
    dropped silently (forgiving — mirrors F.3 / multi-cloud-posture).

    The reader is pure I/O: no classifier calls, no detector logic, no
    side effects beyond the filesystem read.
    """
    return await asyncio.to_thread(_read_sync, path)


def _read_sync(path: Path) -> tuple[BucketInventory, ...]:
    if not path.exists():
        raise S3InventoryReaderError(f"s3 inventory json not found: {path}")
    if not path.is_file():
        raise S3InventoryReaderError(f"s3 inventory json is not a file: {path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            blob = json.load(f)
    except json.JSONDecodeError as exc:
        raise S3InventoryReaderError(f"s3 inventory json is malformed: {exc}") from exc

    raw_records = _extract_records(blob)
    out: list[BucketInventory] = []
    for raw in raw_records:
        rec = _try_parse(raw)
        if rec is not None:
            out.append(rec)
    return tuple(out)


def _extract_records(blob: Any) -> list[dict[str, Any]]:
    """Pull the list of bucket dicts out of the top-level JSON.

    Supports ``{"buckets": [...]}`` (canonical) or a bare list.
    """
    if isinstance(blob, dict):
        if "buckets" in blob:
            buckets = blob["buckets"]
            if isinstance(buckets, list):
                return [b for b in buckets if isinstance(b, dict)]
        return []
    if isinstance(blob, list):
        return [b for b in blob if isinstance(b, dict)]
    return []


def _try_parse(raw: dict[str, Any]) -> BucketInventory | None:
    """Parse one raw bucket dict; return None if validation fails."""
    try:
        return BucketInventory.model_validate(raw)
    except ValidationError:
        return None
