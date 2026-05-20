"""Filesystem-mode S3 readers for the D.5 Data Security agent.

v0.1 readers consume operator-staged JSON snapshots (output of
``aws s3api list-buckets`` + per-bucket ``get-bucket-*`` calls). Live
boto3 SDK calls land in D.5 v0.2 behind the same async wrapper
signatures per the shim-behind-reader pattern (mirrors F.3).
"""

from __future__ import annotations

from data_security.tools.s3_inventory import (
    BucketAcl,
    BucketEncryption,
    BucketInventory,
    PublicAccessBlock,
    S3InventoryReaderError,
    read_s3_inventory,
)
from data_security.tools.s3_objects import (
    ObjectSample,
    S3ObjectsReaderError,
    read_s3_objects,
)

__all__ = [
    "BucketAcl",
    "BucketEncryption",
    "BucketInventory",
    "ObjectSample",
    "PublicAccessBlock",
    "S3InventoryReaderError",
    "S3ObjectsReaderError",
    "read_s3_inventory",
    "read_s3_objects",
]
