"""In-memory cross-cloud aispm harness — path-10 AI leg (gap #13).

Azure OpenAI / Vertex AI have no ``moto``; aispm's readers consume injectable ``AzureAiReader`` /
``GcpAiReader`` Protocols (sources of already-extracted account/endpoint dicts), so small in-memory
fakes ARE the substrate. ``drive_azure_aispm`` / ``drive_gcp_aispm`` run the REAL
``inventory_from_reader`` + ``record_azure`` / ``record_gcp``, writing ``AI_SERVICE``
``EXPOSES_MODEL`` → internet + ``HAS_ACCESS_TO`` → the model-data Blob/bucket keyed by the SAME
canonical key data-security's storage writer uses, so the cloud-agnostic
``find_exposed_ai_with_sensitive_data`` detector (path 10) fires on Azure/GCP with no detector change.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from aispm.kg_writer import KnowledgeGraphWriter as AispmKgWriter
from aispm.tools.azure_ai import inventory_from_reader as azure_inventory
from aispm.tools.gcp_ai import inventory_from_reader as gcp_inventory

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore


@dataclass(frozen=True, slots=True)
class AzureOpenAiSeed:
    """An Azure OpenAI account to seed: name, public-network exposure, model-data Blob."""

    name: str
    public: bool = False
    model_data_account: str = ""
    model_data_container: str = ""


@dataclass(frozen=True, slots=True)
class VertexEndpointSeed:
    """A Vertex endpoint to seed: name, public exposure, model-artifact GCS bucket."""

    name: str
    public: bool = False
    model_data_bucket: str = ""


class _FakeAzureAiReader:
    def __init__(self, accounts: tuple[AzureOpenAiSeed, ...]) -> None:
        self._accounts = accounts

    def openai_accounts(self) -> list[dict[str, Any]]:
        return [
            {
                "name": a.name,
                "public_network_access": a.public,
                "model_data_account": a.model_data_account,
                "model_data_container": a.model_data_container,
            }
            for a in self._accounts
        ]


class _FakeGcpAiReader:
    def __init__(self, endpoints: tuple[VertexEndpointSeed, ...]) -> None:
        self._endpoints = endpoints

    def vertex_endpoints(self) -> list[dict[str, Any]]:
        return [
            {"name": e.name, "public": e.public, "model_data_bucket": e.model_data_bucket}
            for e in self._endpoints
        ]


async def drive_azure_aispm(
    store: SemanticStore,
    *,
    tenant_id: str,
    accounts: tuple[AzureOpenAiSeed, ...],
    subscription_id: str = "sub-1",
) -> None:
    """Run aispm's REAL Azure OpenAI reader + ``record_azure``."""
    inventory = azure_inventory(_FakeAzureAiReader(accounts), subscription_id=subscription_id)
    await AispmKgWriter(store, tenant_id).record_azure(inventory)


async def drive_gcp_aispm(
    store: SemanticStore,
    *,
    tenant_id: str,
    endpoints: tuple[VertexEndpointSeed, ...],
    project_id: str = "acme-prod",
    location: str = "us-central1",
) -> None:
    """Run aispm's REAL Vertex reader + ``record_gcp``."""
    inventory = gcp_inventory(_FakeGcpAiReader(endpoints), project_id=project_id, location=location)
    await AispmKgWriter(store, tenant_id).record_gcp(inventory)


__all__ = [
    "AzureOpenAiSeed",
    "VertexEndpointSeed",
    "drive_azure_aispm",
    "drive_gcp_aispm",
]
