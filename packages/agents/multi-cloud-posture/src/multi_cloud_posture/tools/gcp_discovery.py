"""D.15 GCP project + region discovery (v0.2 Task 7).

Analog to `cloud_posture`'s account/region discovery (Q1 — GCP-native shape).
**Current-project only (Q6** — multi-project / folder / organization enumeration
deferred to v0.3): the project is `GOOGLE_CLOUD_PROJECT`/`GCP_PROJECT` when set,
else the project bound to the resolved ADC credential. Regions are enumerated
for that single project via Compute Engine.

No Resource Manager `projects.list` / organization / folder traversal is called —
listing projects is an org-level operation outside Q6's single-project scope.

Per ADR-005 the SDK calls run on `asyncio.to_thread`; the wrappers are `async`.
"""

from __future__ import annotations

import asyncio
import os

from multi_cloud_posture.credentials_gcp import GcpCredentialResolver


class GcpDiscoveryError(RuntimeError):
    """GCP project / region discovery failed."""


async def discover_project_id(resolver: GcpCredentialResolver) -> str:
    """The current GCP project id (single — Q6).

    `GOOGLE_CLOUD_PROJECT` / `GCP_PROJECT` win; otherwise the project bound to the
    ADC credential. Projects are **not** enumerated (no org-level listing).
    """
    return await asyncio.to_thread(_discover_project_id_sync, resolver)


def _discover_project_id_sync(resolver: GcpCredentialResolver) -> str:
    env_proj = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT")
    if env_proj:
        return env_proj
    _credentials, project = resolver.resolve_credential()
    if project:
        return str(project)
    raise GcpDiscoveryError("no GCP project resolved from the credential or GOOGLE_CLOUD_PROJECT")


async def discover_regions(resolver: GcpCredentialResolver, project_id: str) -> list[str]:
    """Enumerate Compute Engine region names for the single project."""
    return await asyncio.to_thread(_discover_regions_sync, resolver, project_id)


def _discover_regions_sync(resolver: GcpCredentialResolver, project_id: str) -> list[str]:
    from google.cloud import compute_v1

    client = resolver.client(compute_v1.RegionsClient)
    return sorted(region.name for region in client.list(project=project_id) if region.name)
