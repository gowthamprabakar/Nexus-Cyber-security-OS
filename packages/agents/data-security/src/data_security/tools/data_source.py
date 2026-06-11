"""Unified multi-cloud data-source view (data-security v0.2 Task 7).

Normalises S3 buckets + Azure Blob containers + GCS buckets into one `DataSource` shape so
the detectors / privacy-framework mapping work cloud-agnostically (Q1 — 3-cloud parity), and
identifies **cross-cloud replicas** (the same logical dataset present in more than one cloud,
e.g. a backup copy) by logical name.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from data_security.tools.azure_blob_inventory import AzureBlobContainer
from data_security.tools.gcs_inventory import GcsBucket
from data_security.tools.s3_inventory import BucketInventory


class DataCloud(StrEnum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


@dataclass(frozen=True, slots=True)
class DataSource:
    cloud: DataCloud
    identifier: str
    region: str
    is_public: bool
    is_encrypted: bool

    @property
    def logical_name(self) -> str:
        """The cloud-agnostic dataset name — the last path segment, lowercased."""
        return self.identifier.rsplit("/", 1)[-1].lower()


def from_s3(b: BucketInventory) -> DataSource:
    public = bool(b.acl.grants_all_users or b.acl.grants_authenticated_users)
    return DataSource(
        cloud=DataCloud.AWS,
        identifier=b.name,
        region=b.region,
        is_public=public,
        is_encrypted=b.encryption.algorithm != "NONE",
    )


def from_azure(c: AzureBlobContainer) -> DataSource:
    return DataSource(
        cloud=DataCloud.AZURE,
        identifier=f"{c.storage_account}/{c.container}",
        region=c.region,
        is_public=c.is_public,
        is_encrypted=c.encrypted,
    )


def from_gcs(g: GcsBucket) -> DataSource:
    return DataSource(
        cloud=DataCloud.GCP,
        identifier=g.name,
        region=g.location,
        is_public=g.is_public,
        is_encrypted=g.encrypted,
    )


def unify(
    *,
    s3: Sequence[BucketInventory] = (),
    azure: Sequence[AzureBlobContainer] = (),
    gcs: Sequence[GcsBucket] = (),
) -> tuple[DataSource, ...]:
    """Normalise all three clouds' inventories into a single `DataSource` tuple."""
    return (
        *(from_s3(b) for b in s3),
        *(from_azure(c) for c in azure),
        *(from_gcs(g) for g in gcs),
    )


def cross_cloud_replicas(sources: Sequence[DataSource]) -> list[tuple[str, tuple[DataSource, ...]]]:
    """Group sources sharing a logical name across **more than one cloud** (replicas)."""
    by_name: dict[str, list[DataSource]] = {}
    for s in sources:
        by_name.setdefault(s.logical_name, []).append(s)
    out: list[tuple[str, tuple[DataSource, ...]]] = []
    for name, group in sorted(by_name.items()):
        if len({s.cloud for s in group}) > 1:
            out.append((name, tuple(group)))
    return out
