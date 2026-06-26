"""Azure Container Instances workload + internet-exposure reader (path-2 cross-cloud).

The Azure analogue of the ECS reader: an ACI container group runs a container **image** and
can have a public IP, so it is the direct cross-cloud match for "internet-exposed workload
running a vulnerable image" (path 2). Resolves each container group to (a) its container image
ref — the SAME key vulnerability writes CVE ``VULNERABLE_TO`` edges onto — and (b) whether it is
internet-exposed (``ipAddress.type == 'Public'``).

The mechanism-② bridge (ADR-023): vulnerability keys images by ref, the spine keys workloads by
resource id; ``record_azure_workloads`` writes ``RUNS_IMAGE`` joining the workload to the image
node so a graph query reaches an exposed workload's CVEs — identical to ECS, no detector change.
The client is an injectable Protocol, so this is unit-testable without the azure-mgmt SDK.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class AciWorkload:
    """An ACI container group resolved to its image ref + internet-exposure posture."""

    resource_id: str
    image_ref: str
    is_public: bool


class AzureAciReader(Protocol):
    def list_container_groups(self) -> list[dict[str, Any]]: ...


def _first_image(group: dict[str, Any]) -> str:
    """The first container's image ref in a container group. "" when absent."""
    containers = group.get("containers") or []
    if not (isinstance(containers, list) and containers):
        return ""
    props = containers[0].get("properties") if isinstance(containers[0], dict) else None
    image = (props or {}).get("image") if isinstance(props, dict) else None
    return str(image or "")


def _is_public(group: dict[str, Any]) -> bool:
    """Internet-exposed when the container group has a Public IP address."""
    props = group.get("properties")
    ip = props.get("ipAddress") if isinstance(props, dict) else None
    return isinstance(ip, dict) and ip.get("type") == "Public"


def read_aci_workloads(client: AzureAciReader) -> list[AciWorkload]:
    """Enumerate ACI container groups as ``AciWorkload`` rows.

    Skips groups with no resolvable container image (nothing to join to a CVE node).
    """
    out: list[AciWorkload] = []
    for group in client.list_container_groups():
        if not isinstance(group, dict):
            continue
        resource_id = str(group.get("id", ""))
        image_ref = _first_image(group)
        if not (resource_id and image_ref):
            continue
        out.append(AciWorkload(resource_id, image_ref, _is_public(group)))
    return out


__all__ = ["AciWorkload", "AzureAciReader", "read_aci_workloads"]
