"""AWS S3 data-residency tracking (data-security v0.2 Task 4).

Per **Q6 (GDPR)** + the **WI-S10 data-residency boundary** — Nexus's core moat — each bucket
is tagged with the **jurisdiction** of its AWS region. A `ResidencyRecord` carries
**metadata only** (bucket name + region + jurisdiction); it never carries object keys or
content, so residency tracking can leave the edge without violating the boundary.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from data_security.tools.s3_inventory import BucketInventory


class Jurisdiction(StrEnum):
    EU = "eu"
    US = "us"
    APAC = "apac"
    OTHER = "other"


def classify_region(region: str) -> Jurisdiction:
    """Map an AWS region to a data-residency jurisdiction."""
    r = region.lower()
    if r.startswith("eu-"):
        return Jurisdiction.EU
    if r.startswith(("us-", "ca-")):
        return Jurisdiction.US
    if r.startswith("ap-"):
        return Jurisdiction.APAC
    return Jurisdiction.OTHER


@dataclass(frozen=True, slots=True)
class ResidencyRecord:
    """Metadata-only residency record (WI-S10) — NO object keys, NO content."""

    bucket: str
    region: str
    jurisdiction: Jurisdiction

    def to_metadata(self) -> dict[str, str]:
        return {
            "bucket": self.bucket,
            "region": self.region,
            "jurisdiction": self.jurisdiction.value,
        }


def track_residency(buckets: Sequence[BucketInventory]) -> tuple[ResidencyRecord, ...]:
    """Tag each bucket with its region's jurisdiction (metadata only)."""
    return tuple(
        ResidencyRecord(bucket=b.name, region=b.region, jurisdiction=classify_region(b.region))
        for b in buckets
    )


def gdpr_in_scope(record: ResidencyRecord) -> bool:
    """True if the bucket sits in an EU region — within GDPR data-residency scope."""
    return record.jurisdiction is Jurisdiction.EU
