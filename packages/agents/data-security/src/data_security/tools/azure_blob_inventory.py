"""Live Azure Blob Storage inventory + sampling (data-security v0.2 Task 5).

Multi-cloud parity with the S3 path (Q1). Enumerates a storage account's blob containers
into a typed `AzureBlobContainer` (the security-relevant posture: public-access level +
encryption + region) and samples blob content into the **same** `ObjectSample` / `SampleBasis`
shapes the classifier + the sample-basis contract (WI-S12) already use. The Azure client is
an injectable Protocol so this is unit-testable without the azure-storage-blob SDK; the prod
client is built from the charter Pattern A Azure resolver (as adopted by D.5).
"""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, Field

from data_security.tools.s3_objects import MAX_SAMPLE_BYTES, ObjectSample
from data_security.tools.s3_objects_live import DEFAULT_SAMPLE_RATE, SampleBasis, _stride

_PUBLIC_LEVELS = ("blob", "container")


class AzureBlobContainer(BaseModel):
    """One blob container's posture, normalised for the detectors."""

    storage_account: str = Field(min_length=1)
    container: str = Field(min_length=1)
    region: str = Field(min_length=1)
    public_access: str = Field(default="none")  # "none" | "blob" | "container"
    encrypted: bool = True

    @property
    def is_public(self) -> bool:
        return self.public_access in _PUBLIC_LEVELS


class AzureBlobClient(Protocol):
    def list_containers(self) -> list[dict[str, Any]]: ...
    def list_blobs(self, *, container: str) -> list[dict[str, Any]]: ...
    def download_blob(self, *, container: str, blob: str) -> bytes: ...


class AzureBlobLiveReader:
    """Reads live Azure Blob container posture + samples blob content."""

    __slots__ = ("_account", "_client", "_region", "_sample_rate")

    def __init__(
        self,
        client: AzureBlobClient,
        *,
        storage_account: str,
        region: str,
        sample_rate: float = DEFAULT_SAMPLE_RATE,
    ) -> None:
        self._client = client
        self._account = storage_account
        self._region = region
        self._sample_rate = sample_rate

    def read(self) -> tuple[AzureBlobContainer, ...]:
        out: list[AzureBlobContainer] = []
        for raw in self._client.list_containers():
            if not isinstance(raw, dict) or not raw.get("name"):
                continue
            out.append(
                AzureBlobContainer(
                    storage_account=self._account,
                    container=str(raw["name"]),
                    region=self._region,
                    public_access=str(raw.get("public_access", "none") or "none"),
                    encrypted=bool(raw.get("encrypted", True)),
                )
            )
        return tuple(out)

    def sample(self, container: str) -> tuple[tuple[ObjectSample, ...], SampleBasis]:
        blobs = [
            b["name"]
            for b in self._client.list_blobs(container=container)
            if isinstance(b, dict) and b.get("name")
        ]
        selected = blobs[:: _stride(self._sample_rate)]
        samples: list[ObjectSample] = []
        for name in selected:
            content = self._client.download_blob(container=container, blob=name)
            data = content if isinstance(content, bytes) else bytes(content or b"")
            samples.append(
                ObjectSample(bucket=container, key=name, content_sample=data[:MAX_SAMPLE_BYTES])
            )
        basis = SampleBasis(
            objects_scanned=len(samples),
            objects_total_estimate=len(blobs),
            sample_rate=self._sample_rate,
        )
        return tuple(samples), basis
