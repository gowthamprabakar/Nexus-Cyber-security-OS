"""In-memory Azure compute harness — cross-cloud path-2 workload leg (gap #13).

Azure Container Instances has no ``moto``; cloud-posture's ACI reader consumes an injectable
``AzureAciReader`` Protocol, so a small in-memory fake IS the substrate. ``drive_azure_compute``
runs the REAL ``read_aci_workloads`` + ``record_azure_workloads``, writing the SAME
``CLOUD_RESOURCE{is_public}`` + ``RUNS_IMAGE`` vocabulary the ECS workload leg writes (keyed by the
container image ref), so the cloud-agnostic ``find_internet_exposed_vulnerable_workload`` detector
fires on Azure with no detector change once vulnerability writes CVEs onto the same image node.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cloud_posture.tools.azure_aci import read_aci_workloads
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter as CloudPostureKgWriter

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore

_SUB = "00000000-0000-0000-0000-000000000000"
_RG = "rg1"


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


__all__ = ["AciGroup", "drive_azure_compute"]
