"""Multi-cloud KMS attack-path e2e — Azure Key Vault + GCP Cloud KMS (B-1).

Proves ``find_kms_key_access`` and ``find_exposed_kms_key`` fire on Azure Key Vault and
GCP Cloud KMS keys with NO detector change — the detectors are cloud-agnostic (they filter on
``properties["kind"] == "kms-key"``); this test drives the NEW multi-cloud-posture
``record_kms_keys`` writer and the NEW ``azure_key_vault_key_uri`` / ``gcp_kms_key_name``
canonical builders to stamp the spine nodes (B-1). Hermetic: in-memory store only, no SDK calls.

NOTE: ``KmsKeyAccess.kms_key_id`` and ``ExposedKmsKey.resource_id`` carry the *internal*
``entity_id`` (ULID). We resolve back to ``external_id`` via ``store.get_entity`` to verify the
canonical URI was stored correctly.
"""

import pytest
from charter.canonical import azure_key_vault_key_uri, gcp_kms_key_name
from identity.kg_writer import KnowledgeGraphWriter as IdentityKgWriter
from meta_harness.kg_query import KgQuery
from multi_cloud_posture.tools.kg_writer import KmsKeyRecord
from multi_cloud_posture.tools.kg_writer import KnowledgeGraphWriter as MultiCloudKgWriter

from fleet_testkit import in_memory_semantic_store

_TENANT_AZ = "tenant-kms-azure"
_TENANT_GCP = "tenant-kms-gcp"

# Azure Key Vault canonical IDs
_AZ_VAULT = "acme-keyvault"
_AZ_KEY_ACCESS = "crown-key"
_AZ_KEY_PUBLIC = "exposed-key"
_AZ_KEY_ACCESS_URI = azure_key_vault_key_uri(_AZ_VAULT, _AZ_KEY_ACCESS)
_AZ_KEY_PUBLIC_URI = azure_key_vault_key_uri(_AZ_VAULT, _AZ_KEY_PUBLIC)
_AZ_ROLE = "https://acme.azure.com/principals/app-identity"

# GCP Cloud KMS canonical IDs
_GCP_PROJECT = "acme-prod"
_GCP_LOCATION = "us-central1"
_GCP_RING = "prod-keyring"
_GCP_KEY_ACCESS = "crown-key"
_GCP_KEY_PUBLIC = "exposed-key"
_GCP_KEY_ACCESS_NAME = gcp_kms_key_name(_GCP_PROJECT, _GCP_LOCATION, _GCP_RING, _GCP_KEY_ACCESS)
_GCP_KEY_PUBLIC_NAME = gcp_kms_key_name(_GCP_PROJECT, _GCP_LOCATION, _GCP_RING, _GCP_KEY_PUBLIC)
_GCP_SA = f"serviceAccount:app@{_GCP_PROJECT}.iam.gserviceaccount.com"


@pytest.mark.asyncio
async def test_azure_key_vault_kms_key_access_fires() -> None:
    """find_kms_key_access returns a hit for an Azure Key Vault key protecting sensitive data.

    Verifies the canonical URI is the spine node's external_id by resolving the
    entity returned from the hit back to its external_id.
    """
    async with in_memory_semantic_store() as store:
        # Plant Azure KMS key + EXPOSES_DATA edge via multi-cloud-posture writer
        await MultiCloudKgWriter(store, _TENANT_AZ).record_kms_keys(
            [KmsKeyRecord(key_id=_AZ_KEY_ACCESS_URI, is_public=False, data_type="ssn")]
        )
        # Plant IDENTITY --HAS_ACCESS_TO--> kms-key edge via identity writer
        await IdentityKgWriter(store, _TENANT_AZ).record_access([(_AZ_ROLE, _AZ_KEY_ACCESS_URI)])

        hits = await KgQuery(store, _TENANT_AZ).find_kms_key_access()
        assert hits, "Azure Key Vault kms_key_access path must fire"
        assert any(h.data_type == "ssn" for h in hits), "data_type must be 'ssn'"
        # Resolve the internal entity_id back to external_id to confirm canonical URI was stored
        key_entities = [
            await store.get_entity(tenant_id=_TENANT_AZ, entity_id=h.kms_key_id) for h in hits
        ]
        external_ids = {e.external_id for e in key_entities if e is not None}
        assert _AZ_KEY_ACCESS_URI in external_ids, (
            f"Azure Key Vault canonical URI must be the spine node external_id; got {external_ids}"
        )


@pytest.mark.asyncio
async def test_azure_key_vault_exposed_kms_key_fires() -> None:
    """find_exposed_kms_key returns a hit for an Azure Key Vault key with is_public=True."""
    async with in_memory_semantic_store() as store:
        await MultiCloudKgWriter(store, _TENANT_AZ).record_kms_keys(
            [KmsKeyRecord(key_id=_AZ_KEY_PUBLIC_URI, is_public=True)]
        )

        hits = await KgQuery(store, _TENANT_AZ).find_exposed_kms_key()
        assert hits, "Azure Key Vault exposed_kms_key path must fire"
        # Resolve internal resource_id → external_id to verify canonical URI
        resource_entities = [
            await store.get_entity(tenant_id=_TENANT_AZ, entity_id=h.resource_id) for h in hits
        ]
        external_ids = {e.external_id for e in resource_entities if e is not None}
        assert _AZ_KEY_PUBLIC_URI in external_ids, (
            f"Azure Key Vault canonical URI must be the spine node external_id; got {external_ids}"
        )


@pytest.mark.asyncio
async def test_azure_private_key_vault_key_is_dark() -> None:
    """A private Azure Key Vault key (is_public=False, no data_type) produces no hits."""
    async with in_memory_semantic_store() as store:
        await MultiCloudKgWriter(store, _TENANT_AZ).record_kms_keys(
            [KmsKeyRecord(key_id=_AZ_KEY_ACCESS_URI, is_public=False)]
        )
        # No identity access grant — no access path
        assert await KgQuery(store, _TENANT_AZ).find_kms_key_access() == []
        assert await KgQuery(store, _TENANT_AZ).find_exposed_kms_key() == []


@pytest.mark.asyncio
async def test_gcp_cloud_kms_key_access_fires() -> None:
    """find_kms_key_access returns a hit for a GCP Cloud KMS key protecting sensitive data."""
    async with in_memory_semantic_store() as store:
        await MultiCloudKgWriter(store, _TENANT_GCP).record_kms_keys(
            [KmsKeyRecord(key_id=_GCP_KEY_ACCESS_NAME, is_public=False, data_type="phi")]
        )
        await IdentityKgWriter(store, _TENANT_GCP).record_access([(_GCP_SA, _GCP_KEY_ACCESS_NAME)])

        hits = await KgQuery(store, _TENANT_GCP).find_kms_key_access()
        assert hits, "GCP Cloud KMS kms_key_access path must fire"
        assert any(h.data_type == "phi" for h in hits), "data_type must be 'phi'"
        key_entities = [
            await store.get_entity(tenant_id=_TENANT_GCP, entity_id=h.kms_key_id) for h in hits
        ]
        external_ids = {e.external_id for e in key_entities if e is not None}
        assert _GCP_KEY_ACCESS_NAME in external_ids, (
            f"GCP Cloud KMS resource name must be the spine node external_id; got {external_ids}"
        )


@pytest.mark.asyncio
async def test_gcp_cloud_kms_exposed_key_fires() -> None:
    """find_exposed_kms_key returns a hit for a GCP Cloud KMS key with is_public=True."""
    async with in_memory_semantic_store() as store:
        await MultiCloudKgWriter(store, _TENANT_GCP).record_kms_keys(
            [KmsKeyRecord(key_id=_GCP_KEY_PUBLIC_NAME, is_public=True)]
        )

        hits = await KgQuery(store, _TENANT_GCP).find_exposed_kms_key()
        assert hits, "GCP Cloud KMS exposed_kms_key path must fire"
        resource_entities = [
            await store.get_entity(tenant_id=_TENANT_GCP, entity_id=h.resource_id) for h in hits
        ]
        external_ids = {e.external_id for e in resource_entities if e is not None}
        assert _GCP_KEY_PUBLIC_NAME in external_ids, (
            f"GCP Cloud KMS resource name must be the spine node external_id; got {external_ids}"
        )


@pytest.mark.asyncio
async def test_gcp_private_key_is_dark() -> None:
    """A private GCP Cloud KMS key (is_public=False, no data_type) produces no hits."""
    async with in_memory_semantic_store() as store:
        await MultiCloudKgWriter(store, _TENANT_GCP).record_kms_keys(
            [KmsKeyRecord(key_id=_GCP_KEY_ACCESS_NAME, is_public=False)]
        )
        assert await KgQuery(store, _TENANT_GCP).find_kms_key_access() == []
        assert await KgQuery(store, _TENANT_GCP).find_exposed_kms_key() == []
