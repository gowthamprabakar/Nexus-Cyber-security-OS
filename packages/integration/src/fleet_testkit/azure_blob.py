"""In-memory Azure Blob harness — multi-cloud attack-path proof (gap #13, first slice).

Azure has no ``moto``; the data-security Azure reader consumes an injectable ``AzureBlobClient``
Protocol, so a small in-memory fake IS the test substrate. ``drive_azure_data_security`` runs the
REAL ``AzureBlobLiveReader`` + sampler + the real ``classify_bytes`` + the cloud-agnostic
``record_data_sources`` into a ``SemanticStore`` — writing the SAME ``CLOUD_RESOURCE{is_public}`` +
``EXPOSES_DATA`` vocabulary the S3 path writes, so the cloud-agnostic ``kg_query`` detectors
(public-secret, public-unencrypted, …) fire on Azure resources with no detector change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from data_security.classifiers import classify_bytes
from data_security.kg_writer import KnowledgeGraphWriter as DataSecurityKgWriter
from data_security.schemas import ClassifierLabel
from data_security.tools.azure_blob_inventory import AzureBlobLiveReader
from data_security.tools.data_source import from_azure

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore

_DEFAULT_ACCOUNT = "acmestorage"
_DEFAULT_REGION = "eastus"


@dataclass(frozen=True, slots=True)
class AzureContainer:
    """A blob container to seed: name, public-access level, encryption, blob bodies."""

    name: str
    public_access: str = "none"  # "none" | "blob" | "container" ("blob"/"container" = public)
    encrypted: bool = True
    blobs: dict[str, bytes] = field(default_factory=dict)


class _FakeAzureBlobClient:
    """In-memory ``AzureBlobClient`` — the injectable seam the real reader consumes."""

    def __init__(self, containers: tuple[AzureContainer, ...]) -> None:
        self._containers = {c.name: c for c in containers}

    def list_containers(self) -> list[dict[str, object]]:
        return [
            {"name": c.name, "public_access": c.public_access, "encrypted": c.encrypted}
            for c in self._containers.values()
        ]

    def list_blobs(self, *, container: str) -> list[dict[str, object]]:
        return [{"name": name} for name in self._containers[container].blobs]

    def download_blob(self, *, container: str, blob: str) -> bytes:
        return self._containers[container].blobs[blob]


async def drive_azure_data_security(
    store: SemanticStore,
    *,
    tenant_id: str,
    containers: tuple[AzureContainer, ...],
    storage_account: str = _DEFAULT_ACCOUNT,
    region: str = _DEFAULT_REGION,
) -> dict[str, str]:
    """Run data-security's REAL Azure reader + classifier + cloud-agnostic writer.

    Returns ``{container_name: canonical_key}`` (the Azure blob URI written to the graph).
    """
    reader = AzureBlobLiveReader(
        _FakeAzureBlobClient(containers),
        storage_account=storage_account,
        region=region,
        sample_rate=1.0,
    )
    inventory = reader.read()
    sources = [from_azure(c) for c in inventory]

    hits_by_identifier: dict[str, list[ClassifierLabel]] = {}
    for container in inventory:
        samples, _basis = reader.sample(container.container)
        for sample in samples:
            label = classify_bytes(sample.content_sample)
            if label is not ClassifierLabel.NONE:
                hits_by_identifier.setdefault(
                    f"{container.storage_account}/{container.container}", []
                ).append(label)

    await DataSecurityKgWriter(store, tenant_id).record_data_sources(sources, hits_by_identifier)
    return {c.container: from_azure(c).canonical_key for c in inventory}


__all__ = ["AzureContainer", "drive_azure_data_security"]
