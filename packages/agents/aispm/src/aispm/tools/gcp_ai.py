"""GCP Vertex AI discovery connector (D.11 AI-SPM PR3, operator Q1 cloud #3).

Reads a project's Vertex AI endpoints into a typed ``GcpAiInventory`` via the
google-cloud-aiplatform SDK. Same shape as the AWS/Azure connectors: a thin
:class:`GcpAiReader` protocol + pure :func:`inventory_from_reader`; the live
``_AiplatformGcpReader`` is the gated live path. Auth follows the charter credential
contract (google-auth ADC; project/location are source identifiers, no secret material).
No torch.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Protocol


class GcpAiReader(Protocol):
    """Source of already-extracted Vertex endpoint dicts — real SDK or fake."""

    def vertex_endpoints(self) -> list[dict[str, Any]]: ...


@dataclass(frozen=True, slots=True)
class VertexEndpoint:
    name: str
    public: bool | None  # no VPC network attached → reachable publicly
    cmk_encrypted: bool | None  # encryption_spec.kms_key_name set
    psc_enabled: bool | None  # private service connect
    #: The GCS bucket holding the deployed model's artifact (``artifactUri`` = ``gs://<bucket>/…``) —
    #: the model-data link for path 10. HAS_ACCESS_TO joins the endpoint to its training data, keyed
    #: by the same ``gcs_uri`` data-security's storage writer uses. "" when none.
    model_data_bucket: str = ""


@dataclass(frozen=True, slots=True)
class GcpAiInventory:
    project_id: str
    location: str
    endpoints: tuple[VertexEndpoint, ...] = field(default_factory=tuple)
    degraded: tuple[dict[str, str], ...] = field(default_factory=tuple)


def inventory_from_reader(reader: GcpAiReader, *, project_id: str, location: str) -> GcpAiInventory:
    """Pure: build a typed :class:`GcpAiInventory` from a reader's extracted dicts."""
    endpoints = tuple(
        VertexEndpoint(
            name=str(e.get("name", "")),
            public=e.get("public"),
            cmk_encrypted=e.get("cmk_encrypted"),
            psc_enabled=e.get("psc_enabled"),
            model_data_bucket=str(e.get("model_data_bucket", "")),
        )
        for e in reader.vertex_endpoints()
        if e.get("name")
    )
    return GcpAiInventory(project_id=project_id, location=location, endpoints=endpoints)


class _AiplatformGcpReader:
    """Live google-cloud-aiplatform reader (gated live path; NOT exercised in CI)."""

    def __init__(self, *, project_id: str, location: str) -> None:
        from google.cloud import aiplatform_v1

        self._client = aiplatform_v1.EndpointServiceClient()
        self._parent = f"projects/{project_id}/locations/{location}"

    def vertex_endpoints(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for ep in self._client.list_endpoints(parent=self._parent):
            network = getattr(ep, "network", "") or ""
            enc = getattr(ep, "encryption_spec", None)
            psc = getattr(ep, "private_service_connect_config", None)
            out.append(
                {
                    "name": getattr(ep, "display_name", "") or getattr(ep, "name", ""),
                    "public": not network,
                    "cmk_encrypted": bool(getattr(enc, "kms_key_name", "")) if enc else False,
                    "psc_enabled": (
                        bool(getattr(psc, "enable_private_service_connect", False))
                        if psc
                        else False
                    ),
                }
            )
        return out


async def read_gcp_ai(
    *,
    project_id: str,
    location: str = "us-central1",
    reader: GcpAiReader | None = None,
) -> GcpAiInventory:
    """Read a project's Vertex AI posture into a typed inventory."""
    if reader is not None:
        return inventory_from_reader(reader, project_id=project_id, location=location)
    return await asyncio.to_thread(
        lambda: inventory_from_reader(
            _AiplatformGcpReader(project_id=project_id, location=location),
            project_id=project_id,
            location=location,
        )
    )


__all__ = [
    "GcpAiInventory",
    "GcpAiReader",
    "VertexEndpoint",
    "inventory_from_reader",
    "read_gcp_ai",
]
