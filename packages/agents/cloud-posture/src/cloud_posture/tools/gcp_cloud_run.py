"""GCP Cloud Run workload + internet-exposure reader (path-2 cross-cloud).

The GCP analogue of the ECS / Azure-ACI readers: a Cloud Run service runs a container **image**
and is internet-exposed when it allows unauthenticated invocation (``allUsers`` holds
``roles/run.invoker``) — the direct match for "internet-exposed workload running a vulnerable
image" (path 2). Resolves each service to its container image ref (the SAME key vulnerability
writes CVEs onto) + its public-invoke posture.

Mechanism-② bridge (ADR-023): ``record_gcp_workloads`` writes ``RUNS_IMAGE`` joining the service to
the image node so an exposed service's CVEs are reachable in one graph walk — no detector change.
The client is an injectable Protocol, so this is unit-testable without the google-cloud-run SDK.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

#: The IAM member that makes a Cloud Run service publicly invocable.
_PUBLIC_INVOKER = "allUsers"


@dataclass(frozen=True, slots=True)
class CloudRunWorkload:
    """A Cloud Run service resolved to its image ref + public-invoke posture + service account."""

    resource_id: str
    image_ref: str
    is_public: bool
    #: The runtime service account, as the IAM member key (``serviceAccount:<email>``) so it joins
    #: the same IDENTITY node a bucket IAM binding grants — the crown-jewel ASSUMES leg (path 5).
    #: "" when the service has no configured service account.
    service_account: str = ""


class GcpCloudRunReader(Protocol):
    def list_services(self) -> list[dict[str, Any]]: ...


def _first_image(service: dict[str, Any]) -> str:
    """The first container's image in a service's template. "" when absent."""
    template = service.get("template")
    containers = template.get("containers") if isinstance(template, dict) else None
    if not (isinstance(containers, list) and containers):
        return ""
    first = containers[0]
    return str(first.get("image", "")) if isinstance(first, dict) else ""


def _is_public(service: dict[str, Any]) -> bool:
    """Internet-exposed when ``allUsers`` can invoke (the run.invoker binding members)."""
    invokers = service.get("invokers", [])
    return isinstance(invokers, list) and _PUBLIC_INVOKER in invokers


def _service_account(service: dict[str, Any]) -> str:
    """The runtime SA as the IAM member key ``serviceAccount:<email>``. "" when absent."""
    template = service.get("template")
    email = template.get("serviceAccount", "") if isinstance(template, dict) else ""
    return f"serviceAccount:{email}" if email else ""


def read_cloud_run_workloads(client: GcpCloudRunReader) -> list[CloudRunWorkload]:
    """Enumerate Cloud Run services as ``CloudRunWorkload`` rows.

    Skips services with no resolvable container image (nothing to join to a CVE node).
    """
    out: list[CloudRunWorkload] = []
    for service in client.list_services():
        if not isinstance(service, dict):
            continue
        resource_id = str(service.get("name", ""))
        image_ref = _first_image(service)
        if not (resource_id and image_ref):
            continue
        out.append(
            CloudRunWorkload(resource_id, image_ref, _is_public(service), _service_account(service))
        )
    return out


__all__ = ["CloudRunWorkload", "GcpCloudRunReader", "read_cloud_run_workloads"]
