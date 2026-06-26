"""Multi-cloud (gap #13, first slice) — Azure Blob public + sensitive data, REAL e2e.

Proves paths 3 (public secret) and 7 (public + unencrypted + sensitive) work on AZURE through the
agents' own code: a public Azure Blob container + sensitive blobs is read by data-security's real
Azure reader, classified by the real classifier, and written to the graph as the SAME
``CLOUD_RESOURCE{is_public}`` + ``EXPOSES_DATA`` vocabulary (keyed by the Azure blob URI). The
cloud-agnostic ``KgQuery`` detectors then fire with NO detector change — the attack-path engine is
genuinely multi-cloud. Hermetic (in-memory Azure client; no SDK, no moto).
"""

import pytest
from charter.canonical import azure_blob_uri
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.azure_blob import AzureContainer, drive_azure_data_security

_TENANT = "tenant-azure"
_ACCOUNT = "acmestorage"
_AWS_KEY = b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
_SSN = b"patient ssn 123-45-6789 on file\n"


@pytest.mark.asyncio
async def test_public_azure_container_with_secret_lights_up_path3() -> None:
    containers = (AzureContainer("creds", public_access="container", blobs={"key.txt": _AWS_KEY}),)
    async with in_memory_semantic_store() as store:
        keys = await drive_azure_data_security(
            store, tenant_id=_TENANT, containers=containers, storage_account=_ACCOUNT
        )
        assert keys["creds"] == azure_blob_uri(_ACCOUNT, "creds")
        hits = await KgQuery(store, _TENANT).find_public_secret_exposure()
        assert len(hits) == 1
        assert hits[0].data_type == "aws_access_key"


@pytest.mark.asyncio
async def test_public_unencrypted_azure_container_with_pii_lights_up_path7() -> None:
    containers = (
        AzureContainer("hr", public_access="blob", encrypted=False, blobs={"e.csv": _SSN}),
    )
    async with in_memory_semantic_store() as store:
        await drive_azure_data_security(store, tenant_id=_TENANT, containers=containers)
        hits = await KgQuery(store, _TENANT).find_public_unencrypted_exposure()
        assert len(hits) == 1
        assert hits[0].data_type == "ssn"


@pytest.mark.asyncio
async def test_private_azure_container_is_dark() -> None:
    # A private container (public_access="none") → no EXPOSES_DATA → no hit.
    containers = (AzureContainer("priv", public_access="none", blobs={"key.txt": _AWS_KEY}),)
    async with in_memory_semantic_store() as store:
        await drive_azure_data_security(store, tenant_id=_TENANT, containers=containers)
        assert await KgQuery(store, _TENANT).find_public_secret_exposure() == []
