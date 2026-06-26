"""Cross-cloud path 5 (gap #13) — the crown-jewel 4-hop on Azure AND GCP, REAL e2e.

Assembles every cross-cloud leg already built, on one workload pivot:
``is_public`` workload (ACI / Cloud Run) that ``RUNS_IMAGE`` a ``VULNERABLE_TO`` image (real trivy)
AND ``ASSUMES`` a managed identity / service account that ``HAS_ACCESS_TO`` a public container/bucket
that ``EXPOSES_DATA`` sensitive data → ``find_crown_jewel_exposure`` lights up. All legs written by
the agents' REAL code; the only AWS→Azure/GCP change is the workload's identity field (managed
identity / service account), so the cloud-agnostic detector fires with no change. Trivy-gated.
"""

import pytest
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.azure_blob import AzureContainer, drive_azure_data_security
from fleet_testkit.cross_cloud_compute import (
    AciGroup,
    CloudRunService,
    drive_azure_compute,
    drive_gcp_compute,
)
from fleet_testkit.gcs_blob import PUBLIC_MEMBER, GcsBucketSeed, drive_gcs_data_security
from fleet_testkit.identity_access import (
    AzureGrant,
    GcpBinding,
    drive_azure_identity_access,
    drive_gcp_identity_access,
)
from fleet_testkit.vuln_scan import drive_vulnerability, trivy_available

pytestmark = pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")

_TENANT = "tenant-xcloud-crown"
_ACCOUNT = "acmestorage"
_IMAGE_REF = "myreg/app:1.0"
_SSN = b"patient ssn 123-45-6789 on file\n"
_MI = "mi-web-1"  # Azure managed-identity principal
_SA = "serviceAccount:web@acme-prod.iam.gserviceaccount.com"  # Cloud Run SA (member key)


def _write_vulnerable_fixture(root) -> None:
    (root / "requirements.txt").write_text("Django==2.0.0\n")


def _azure_scope(container: str) -> str:
    return (
        f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage"
        f"/storageAccounts/{_ACCOUNT}/blobServices/default/containers/{container}"
    )


@pytest.mark.asyncio
async def test_azure_crown_jewel_lights_up(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    async with in_memory_semantic_store() as store:
        # data leg: public container with sensitive data (EXPOSES_DATA)
        containers = (AzureContainer("crown", public_access="container", blobs={"e.csv": _SSN}),)
        await drive_azure_data_security(
            store, tenant_id=_TENANT, containers=containers, storage_account=_ACCOUNT
        )
        # compute + vuln legs: exposed ACI running a vulnerable image, ASSUMES the managed identity
        await drive_azure_compute(
            store,
            tenant_id=_TENANT,
            groups=(AciGroup("web", image=_IMAGE_REF, public=True, identity_principal_id=_MI),),
        )
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_IMAGE_REF
        )
        # access leg: the managed identity can read the crown container
        await drive_azure_identity_access(
            store,
            tenant_id=_TENANT,
            grants=(AzureGrant(_MI, "Storage Blob Data Reader", _azure_scope("crown")),),
        )
        hits = await KgQuery(store, _TENANT).find_crown_jewel_exposure()
        assert hits, "exposed+vulnerable Azure workload whose identity reaches data = crown jewel"
        assert all(h.cve_id and h.data_type == "ssn" for h in hits)


@pytest.mark.asyncio
async def test_azure_crown_jewel_dark_without_data_access(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    async with in_memory_semantic_store() as store:
        containers = (AzureContainer("crown", public_access="container", blobs={"e.csv": _SSN}),)
        await drive_azure_data_security(
            store, tenant_id=_TENANT, containers=containers, storage_account=_ACCOUNT
        )
        await drive_azure_compute(
            store,
            tenant_id=_TENANT,
            groups=(AciGroup("web", image=_IMAGE_REF, public=True, identity_principal_id=_MI),),
        )
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_IMAGE_REF
        )
        # The identity is granted a DIFFERENT container → cannot reach the crown data.
        await drive_azure_identity_access(
            store,
            tenant_id=_TENANT,
            grants=(AzureGrant(_MI, "Storage Blob Data Reader", _azure_scope("other")),),
        )
        assert await KgQuery(store, _TENANT).find_crown_jewel_exposure() == []


@pytest.mark.asyncio
async def test_gcp_crown_jewel_lights_up(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    async with in_memory_semantic_store() as store:
        buckets = (GcsBucketSeed("crown", iam_members=(PUBLIC_MEMBER,), blobs={"e.csv": _SSN}),)
        await drive_gcs_data_security(store, tenant_id=_TENANT, buckets=buckets)
        await drive_gcp_compute(
            store,
            tenant_id=_TENANT,
            services=(
                CloudRunService(
                    "web",
                    image=_IMAGE_REF,
                    public=True,
                    service_account="web@acme-prod.iam.gserviceaccount.com",
                ),
            ),
        )
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_IMAGE_REF
        )
        await drive_gcp_identity_access(
            store,
            tenant_id=_TENANT,
            bindings=(GcpBinding("crown", "roles/storage.objectViewer", (_SA,)),),
        )
        hits = await KgQuery(store, _TENANT).find_crown_jewel_exposure()
        assert hits, "exposed+vulnerable Cloud Run service whose SA reaches data = crown jewel"
        assert all(h.cve_id and h.data_type == "ssn" for h in hits)


@pytest.mark.asyncio
async def test_gcp_crown_jewel_dark_without_data_access(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    async with in_memory_semantic_store() as store:
        buckets = (GcsBucketSeed("crown", iam_members=(PUBLIC_MEMBER,), blobs={"e.csv": _SSN}),)
        await drive_gcs_data_security(store, tenant_id=_TENANT, buckets=buckets)
        await drive_gcp_compute(
            store,
            tenant_id=_TENANT,
            services=(
                CloudRunService(
                    "web",
                    image=_IMAGE_REF,
                    public=True,
                    service_account="web@acme-prod.iam.gserviceaccount.com",
                ),
            ),
        )
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_IMAGE_REF
        )
        # SA granted a DIFFERENT bucket → cannot reach the crown data.
        await drive_gcp_identity_access(
            store,
            tenant_id=_TENANT,
            bindings=(GcpBinding("other", "roles/storage.objectViewer", (_SA,)),),
        )
        assert await KgQuery(store, _TENANT).find_crown_jewel_exposure() == []
