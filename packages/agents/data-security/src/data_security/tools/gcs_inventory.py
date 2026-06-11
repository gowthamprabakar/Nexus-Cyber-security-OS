"""Live Google Cloud Storage inventory + sampling (data-security v0.2 Task 6).

Multi-cloud parity sensor #3 (Q1). Enumerates a project's GCS buckets into a typed
`GcsBucket` (public-via-IAM + encryption + location) and samples blob content into the
**same** `ObjectSample` / `SampleBasis` shapes the classifier + WI-S12 contract use. The GCS
client is an injectable Protocol so this is unit-testable without the google-cloud-storage
SDK; the prod client is built from the charter Pattern A GCP resolver (as adopted by D.5).
"""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, Field

from data_security.tools.s3_objects import MAX_SAMPLE_BYTES, ObjectSample
from data_security.tools.s3_objects_live import DEFAULT_SAMPLE_RATE, SampleBasis, _stride

#: GCS IAM members that make a bucket public.
_PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})


class GcsBucket(BaseModel):
    """One GCS bucket's posture, normalised for the detectors."""

    project: str = Field(min_length=1)
    name: str = Field(min_length=1)
    location: str = Field(min_length=1)
    iam_members: tuple[str, ...] = Field(default_factory=tuple)
    encrypted: bool = True

    @property
    def is_public(self) -> bool:
        return bool(set(self.iam_members) & _PUBLIC_MEMBERS)


class GcsClient(Protocol):
    def list_buckets(self) -> list[dict[str, Any]]: ...
    def list_blobs(self, *, bucket: str) -> list[dict[str, Any]]: ...
    def download_blob(self, *, bucket: str, blob: str) -> bytes: ...


class GcsLiveReader:
    """Reads live GCS bucket posture + samples blob content."""

    __slots__ = ("_client", "_project", "_sample_rate")

    def __init__(
        self, client: GcsClient, *, project: str, sample_rate: float = DEFAULT_SAMPLE_RATE
    ) -> None:
        self._client = client
        self._project = project
        self._sample_rate = sample_rate

    def read(self) -> tuple[GcsBucket, ...]:
        out: list[GcsBucket] = []
        for raw in self._client.list_buckets():
            if not isinstance(raw, dict) or not raw.get("name"):
                continue
            members = raw.get("iam_members", [])
            out.append(
                GcsBucket(
                    project=self._project,
                    name=str(raw["name"]),
                    location=str(raw.get("location", "US")),
                    iam_members=tuple(str(m) for m in members) if isinstance(members, list) else (),
                    encrypted=bool(raw.get("encrypted", True)),
                )
            )
        return tuple(out)

    def sample(self, bucket: str) -> tuple[tuple[ObjectSample, ...], SampleBasis]:
        blobs = [
            b["name"]
            for b in self._client.list_blobs(bucket=bucket)
            if isinstance(b, dict) and b.get("name")
        ]
        selected = blobs[:: _stride(self._sample_rate)]
        samples: list[ObjectSample] = []
        for name in selected:
            content = self._client.download_blob(bucket=bucket, blob=name)
            data = content if isinstance(content, bytes) else bytes(content or b"")
            samples.append(
                ObjectSample(bucket=bucket, key=name, content_sample=data[:MAX_SAMPLE_BYTES])
            )
        basis = SampleBasis(
            objects_scanned=len(samples),
            objects_total_estimate=len(blobs),
            sample_rate=self._sample_rate,
        )
        return tuple(samples), basis
