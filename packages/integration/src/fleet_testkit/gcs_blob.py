"""In-memory GCS harness — multi-cloud attack-path proof (gap #13, GCS parity).

Like the Azure harness, GCS has no ``moto``; the data-security GCS reader consumes an injectable
``GcsClient`` Protocol, so a small in-memory fake IS the test substrate. ``drive_gcs_data_security``
runs the REAL ``GcsLiveReader`` + sampler + the real ``classify_bytes`` + the cloud-agnostic
``record_data_sources`` into a ``SemanticStore`` — writing the SAME ``CLOUD_RESOURCE{is_public}`` +
``EXPOSES_DATA`` vocabulary the S3/Azure paths write (keyed by the ``gs://`` URI), so the
cloud-agnostic ``kg_query`` detectors fire on GCS resources with no detector change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from data_security.classifiers import classify_bytes
from data_security.kg_writer import KnowledgeGraphWriter as DataSecurityKgWriter
from data_security.schemas import ClassifierLabel
from data_security.tools.data_source import from_gcs
from data_security.tools.gcs_inventory import GcsLiveReader

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore

_DEFAULT_PROJECT = "acme-prod"
_DEFAULT_LOCATION = "US"
#: An IAM member that makes a bucket public (matches gcs_inventory._PUBLIC_MEMBERS).
PUBLIC_MEMBER = "allUsers"


@dataclass(frozen=True, slots=True)
class GcsBucketSeed:
    """A bucket to seed: name, public IAM members, encryption, blob bodies."""

    name: str
    iam_members: tuple[str, ...] = ()  # include PUBLIC_MEMBER to make it public
    encrypted: bool = True
    blobs: dict[str, bytes] = field(default_factory=dict)


class _FakeGcsClient:
    """In-memory ``GcsClient`` — the injectable seam the real reader consumes."""

    def __init__(self, buckets: tuple[GcsBucketSeed, ...]) -> None:
        self._buckets = {b.name: b for b in buckets}

    def list_buckets(self) -> list[dict[str, Any]]:
        return [
            {
                "name": b.name,
                "location": _DEFAULT_LOCATION,
                "iam_members": list(b.iam_members),
                "encrypted": b.encrypted,
            }
            for b in self._buckets.values()
        ]

    def list_blobs(self, *, bucket: str) -> list[dict[str, Any]]:
        return [{"name": name} for name in self._buckets[bucket].blobs]

    def download_blob(self, *, bucket: str, blob: str) -> bytes:
        return self._buckets[bucket].blobs[blob]


async def drive_gcs_data_security(
    store: SemanticStore,
    *,
    tenant_id: str,
    buckets: tuple[GcsBucketSeed, ...],
    project: str = _DEFAULT_PROJECT,
) -> dict[str, str]:
    """Run data-security's REAL GCS reader + classifier + cloud-agnostic writer.

    Returns ``{bucket_name: canonical_key}`` (the ``gs://`` URI written to the graph).
    """
    reader = GcsLiveReader(_FakeGcsClient(buckets), project=project, sample_rate=1.0)
    inventory = reader.read()
    sources = [from_gcs(g) for g in inventory]

    hits_by_identifier: dict[str, list[ClassifierLabel]] = {}
    for bucket in inventory:
        samples, _basis = reader.sample(bucket.name)
        for sample in samples:
            label = classify_bytes(sample.content_sample)
            if label is not ClassifierLabel.NONE:
                hits_by_identifier.setdefault(bucket.name, []).append(label)

    await DataSecurityKgWriter(store, tenant_id).record_data_sources(sources, hits_by_identifier)
    return {g.name: from_gcs(g).canonical_key for g in inventory}


__all__ = ["PUBLIC_MEMBER", "GcsBucketSeed", "drive_gcs_data_security"]
