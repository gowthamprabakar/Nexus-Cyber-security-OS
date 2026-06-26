"""Cross-cloud identity access leg (gap #13) — path 4 on Azure AND GCP, REAL e2e.

Proves the fine-grained-data-exposure detector (path 4) works cross-cloud: a public Azure Blob
container / GCS bucket with sensitive data (storage leg) PLUS an Azure AD principal / GCP IAM member
granted fine-grained read on it (identity leg) lights up ``find_fine_grained_data_exposure`` — both
legs written by the agents' REAL code onto the SAME canonical resource node, NO detector change.
Hermetic (in-memory injectable clients; no SDK, no moto).
"""

import pytest
from charter.canonical import azure_blob_uri, gcs_uri
from charter.memory.graph_types import NodeCategory
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.azure_blob import AzureContainer, drive_azure_data_security
from fleet_testkit.gcs_blob import PUBLIC_MEMBER, GcsBucketSeed, drive_gcs_data_security
from fleet_testkit.identity_access import (
    AzureGrant,
    GcpBinding,
    drive_azure_identity_access,
    drive_gcp_identity_access,
)

_TENANT = "tenant-xcloud"
_ACCOUNT = "acmestorage"
_SSN = b"patient ssn 123-45-6789 on file\n"


def _azure_container_scope(account: str, container: str) -> str:
    return (
        f"/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage"
        f"/storageAccounts/{account}/blobServices/default/containers/{container}"
    )


async def _identity_id(store: object, external_id: str) -> str | None:
    """Map a principal's external key to its internal entity_id (what the detector returns)."""
    rows = await store.list_entities_by_type(  # type: ignore[attr-defined]
        tenant_id=_TENANT, entity_type=NodeCategory.IDENTITY.value
    )
    return next((r.entity_id for r in rows if r.external_id == external_id), None)


@pytest.mark.asyncio
async def test_azure_principal_with_blob_read_lights_up_path4() -> None:
    containers = (AzureContainer("reports", public_access="container", blobs={"e.csv": _SSN}),)
    grant = AzureGrant(
        "sp-analyst", "Storage Blob Data Reader", _azure_container_scope(_ACCOUNT, "reports")
    )
    async with in_memory_semantic_store() as store:
        await drive_azure_data_security(
            store, tenant_id=_TENANT, containers=containers, storage_account=_ACCOUNT
        )
        resolved = await drive_azure_identity_access(store, tenant_id=_TENANT, grants=(grant,))
        assert resolved == [("sp-analyst", azure_blob_uri(_ACCOUNT, "reports"))]
        principal_id = await _identity_id(store, "sp-analyst")
        hits = await KgQuery(store, _TENANT).find_fine_grained_data_exposure()
        assert len(hits) == 1
        assert hits[0].principal_id == principal_id
        assert hits[0].data_type == "ssn"


@pytest.mark.asyncio
async def test_azure_principal_scoped_elsewhere_is_dark() -> None:
    containers = (AzureContainer("reports", public_access="container", blobs={"e.csv": _SSN}),)
    grant = AzureGrant(
        "sp-analyst", "Storage Blob Data Reader", _azure_container_scope(_ACCOUNT, "other")
    )
    async with in_memory_semantic_store() as store:
        await drive_azure_data_security(
            store, tenant_id=_TENANT, containers=containers, storage_account=_ACCOUNT
        )
        await drive_azure_identity_access(store, tenant_id=_TENANT, grants=(grant,))
        assert await KgQuery(store, _TENANT).find_fine_grained_data_exposure() == []


@pytest.mark.asyncio
async def test_gcp_member_with_object_read_lights_up_path4() -> None:
    buckets = (GcsBucketSeed("reports", iam_members=(PUBLIC_MEMBER,), blobs={"e.csv": _SSN}),)
    binding = GcpBinding(
        "reports", "roles/storage.objectViewer", ("serviceAccount:analyst@proj.iam",)
    )
    async with in_memory_semantic_store() as store:
        await drive_gcs_data_security(store, tenant_id=_TENANT, buckets=buckets)
        resolved = await drive_gcp_identity_access(store, tenant_id=_TENANT, bindings=(binding,))
        assert resolved == [("serviceAccount:analyst@proj.iam", gcs_uri("reports"))]
        principal_id = await _identity_id(store, "serviceAccount:analyst@proj.iam")
        hits = await KgQuery(store, _TENANT).find_fine_grained_data_exposure()
        assert len(hits) == 1
        assert hits[0].principal_id == principal_id
        assert hits[0].data_type == "ssn"


@pytest.mark.asyncio
async def test_gcp_member_on_other_bucket_is_dark() -> None:
    buckets = (GcsBucketSeed("reports", iam_members=(PUBLIC_MEMBER,), blobs={"e.csv": _SSN}),)
    binding = GcpBinding(
        "other", "roles/storage.objectViewer", ("serviceAccount:analyst@proj.iam",)
    )
    async with in_memory_semantic_store() as store:
        await drive_gcs_data_security(store, tenant_id=_TENANT, buckets=buckets)
        await drive_gcp_identity_access(store, tenant_id=_TENANT, bindings=(binding,))
        assert await KgQuery(store, _TENANT).find_fine_grained_data_exposure() == []
