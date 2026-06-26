"""In-memory cross-cloud compute harness (Azure ACI + GCP Cloud Run) — path-2 workload leg (gap #13).

Azure Container Instances / GCP Cloud Run have no ``moto``; cloud-posture's readers consume
injectable Protocols, so small in-memory fakes ARE the substrate. ``drive_azure_compute`` /
``drive_gcp_compute`` run the REAL readers + writers, writing the SAME ``CLOUD_RESOURCE{is_public}``
+ ``RUNS_IMAGE`` vocabulary the ECS workload leg writes (keyed by the container image ref), so the
cloud-agnostic ``find_internet_exposed_vulnerable_workload`` detector fires on Azure/GCP with no
detector change once vulnerability writes CVEs onto the same image node.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cloud_posture.tools.azure_aci import read_aci_workloads
from cloud_posture.tools.gcp_cloud_run import read_cloud_run_workloads
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter as CloudPostureKgWriter

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore

_SUB = "00000000-0000-0000-0000-000000000000"
_RG = "rg1"
_PROJECT = "acme-prod"
_LOCATION = "us-central1"


def _container_group_id(name: str) -> str:
    return (
        f"/subscriptions/{_SUB}/resourceGroups/{_RG}"
        f"/providers/Microsoft.ContainerInstance/containerGroups/{name}"
    )


@dataclass(frozen=True, slots=True)
class AciGroup:
    """A container group to seed: name, container image ref, internet-exposure."""

    name: str
    image: str
    public: bool = False


class _FakeAciClient:
    """In-memory ``AzureAciReader`` — shaped like the azure-mgmt ContainerInstance payload."""

    def __init__(self, groups: tuple[AciGroup, ...]) -> None:
        self._groups = groups

    def list_container_groups(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for g in self._groups:
            properties: dict[str, Any] = {}
            if g.public:
                properties["ipAddress"] = {"type": "Public", "ip": "20.1.2.3"}
            out.append(
                {
                    "id": _container_group_id(g.name),
                    "containers": [{"name": g.name, "properties": {"image": g.image}}],
                    "properties": properties,
                }
            )
        return out


async def drive_azure_compute(
    store: SemanticStore, *, tenant_id: str, groups: tuple[AciGroup, ...]
) -> dict[str, str]:
    """Run cloud-posture's REAL ACI reader + workload writer. Returns ``{name: resource_id}``."""
    workloads = read_aci_workloads(_FakeAciClient(groups))
    await CloudPostureKgWriter(store, tenant_id).record_azure_workloads(workloads)
    return {g.name: _container_group_id(g.name) for g in groups}


def _service_name(name: str) -> str:
    return f"projects/{_PROJECT}/locations/{_LOCATION}/services/{name}"


@dataclass(frozen=True, slots=True)
class CloudRunService:
    """A Cloud Run service to seed: name, container image ref, public-invoke (allUsers)."""

    name: str
    image: str
    public: bool = False


class _FakeCloudRunClient:
    """In-memory ``GcpCloudRunReader`` — shaped like the Cloud Run v2 service payload."""

    def __init__(self, services: tuple[CloudRunService, ...]) -> None:
        self._services = services

    def list_services(self) -> list[dict[str, Any]]:
        return [
            {
                "name": _service_name(s.name),
                "template": {"containers": [{"image": s.image}]},
                "invokers": ["allUsers"] if s.public else [],
            }
            for s in self._services
        ]


async def drive_gcp_compute(
    store: SemanticStore, *, tenant_id: str, services: tuple[CloudRunService, ...]
) -> dict[str, str]:
    """Run cloud-posture's REAL Cloud Run reader + workload writer. Returns ``{name: resource_id}``."""
    workloads = read_cloud_run_workloads(_FakeCloudRunClient(services))
    await CloudPostureKgWriter(store, tenant_id).record_gcp_workloads(workloads)
    return {s.name: _service_name(s.name) for s in services}


__all__ = ["AciGroup", "CloudRunService", "drive_azure_compute", "drive_gcp_compute"]
