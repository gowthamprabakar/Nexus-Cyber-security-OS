"""In-memory cross-cloud identity-access harness — access leg of gap #13 (paths 4/8).

Azure RBAC and GCP IAM have no ``moto``; identity's readers consume injectable Protocols, so small
in-memory fakes ARE the substrate. These drivers run the REAL grant resolvers
(``azure_rbac.blob_read_grants`` / ``gcp_iam.storage_read_grants``) + identity's REAL
``record_access`` writer, landing ``IDENTITY --HAS_ACCESS_TO--> CLOUD_RESOURCE`` edges on the SAME
canonical resource keys the storage writer uses — so the cloud-agnostic ``kg_query`` access-leg
detectors fire on Azure/GCP with no detector change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from identity.tools.azure_rbac import AzureRbacLiveReader, blob_read_grants, external_trust_grants
from identity.tools.gcp_iam import GcpIamLiveReader, storage_read_grants
from identity.tools.gcp_iam import external_trust_grants as gcp_external_trust_grants

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore


@dataclass(frozen=True, slots=True)
class AzureGrant:
    """A role assignment to seed: principal, role name, scope (an Azure resource id)."""

    principal_id: str
    role_name: str
    scope: str


@dataclass(frozen=True, slots=True)
class GcpBinding:
    """A bucket IAM binding to seed: bucket, role, members."""

    bucket: str
    role: str
    members: tuple[str, ...] = field(default_factory=tuple)


class _FakeAzureRbacClient:
    def __init__(self, grants: tuple[AzureGrant, ...]) -> None:
        self._grants = grants

    def list_role_assignments(self) -> list[dict[str, Any]]:
        return [
            {"principal_id": g.principal_id, "role_name": g.role_name, "scope": g.scope}
            for g in self._grants
        ]


class _FakeGcpIamClient:
    def __init__(self, bindings: tuple[GcpBinding, ...]) -> None:
        self._bindings = bindings

    def list_bucket_bindings(self) -> list[dict[str, Any]]:
        return [
            {"bucket": b.bucket, "role": b.role, "members": list(b.members)} for b in self._bindings
        ]


async def drive_azure_identity_access(
    store: SemanticStore, *, tenant_id: str, grants: tuple[AzureGrant, ...]
) -> list[tuple[str, str]]:
    """Run identity's REAL Azure RBAC resolver + ``record_access``. Returns the grant tuples."""
    assignments = AzureRbacLiveReader(_FakeAzureRbacClient(grants)).read()
    resolved = blob_read_grants(assignments)
    await IdentityKgWriter(store, tenant_id).record_access(resolved)
    return resolved


async def drive_gcp_identity_access(
    store: SemanticStore, *, tenant_id: str, bindings: tuple[GcpBinding, ...]
) -> list[tuple[str, str]]:
    """Run identity's REAL GCP IAM resolver + ``record_access``. Returns the grant tuples."""
    parsed = GcpIamLiveReader(_FakeGcpIamClient(bindings)).read()
    resolved = storage_read_grants(parsed)
    await IdentityKgWriter(store, tenant_id).record_access(resolved)
    return resolved


async def drive_azure_identity_external_trust(
    store: SemanticStore,
    *,
    tenant_id: str,
    grants: tuple[AzureGrant, ...],
    guest_principal_ids: frozenset[str],
) -> list[tuple[str, str]]:
    """Run identity's REAL Azure guest-trust resolver + ``record_access`` + ``record_external_trust``.

    ``guest_principal_ids`` is what identity's AD listing derives from ``AzureAdUser.is_guest``.
    Returns the external-trust grant tuples (path 8).
    """
    assignments = AzureRbacLiveReader(_FakeAzureRbacClient(grants)).read()
    resolved = external_trust_grants(assignments, guest_principal_ids)
    writer = IdentityKgWriter(store, tenant_id)
    await writer.record_access(resolved)
    await writer.record_external_trust([p for p, _ in resolved])
    return resolved


async def drive_gcp_identity_external_trust(
    store: SemanticStore, *, tenant_id: str, bindings: tuple[GcpBinding, ...], org_domain: str
) -> list[tuple[str, str]]:
    """Run identity's REAL GCP external-member resolver + ``record_access`` + ``record_external_trust``.

    Foreign members (outside ``org_domain``, plus ``allAuthenticatedUsers``) with object read are
    marked externally trusted (path 8). Returns the external-trust grant tuples.
    """
    parsed = GcpIamLiveReader(_FakeGcpIamClient(bindings)).read()
    resolved = gcp_external_trust_grants(parsed, org_domain=org_domain)
    writer = IdentityKgWriter(store, tenant_id)
    await writer.record_access(resolved)
    await writer.record_external_trust([m for m, _ in resolved])
    return resolved


__all__ = [
    "AzureGrant",
    "GcpBinding",
    "drive_azure_identity_access",
    "drive_azure_identity_external_trust",
    "drive_gcp_identity_access",
    "drive_gcp_identity_external_trust",
]
