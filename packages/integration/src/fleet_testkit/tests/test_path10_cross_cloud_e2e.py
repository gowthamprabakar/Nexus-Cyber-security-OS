"""Cross-cloud path 10 (gap #13) — exposed AI service + sensitive training data, REAL e2e.

Proves ``find_exposed_ai_with_sensitive_data`` works cross-cloud: a public Azure OpenAI account /
Vertex endpoint (EXPOSES_MODEL → internet) whose model-data Blob/bucket is public + sensitive
(EXPOSES_DATA) lights up path 10. The AI leg is aispm's REAL reader + ``record_azure``/``record_gcp``
(injectable client, no SDK); the data leg is data-security's REAL storage path — both write the SAME
canonical resource node, so the cloud-agnostic detector fires with no change. Hermetic.
"""

import pytest
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.azure_blob import AzureContainer, drive_azure_data_security
from fleet_testkit.cross_cloud_aispm import (
    AzureOpenAiSeed,
    VertexEndpointSeed,
    drive_azure_aispm,
    drive_gcp_aispm,
)
from fleet_testkit.gcs_blob import PUBLIC_MEMBER, GcsBucketSeed, drive_gcs_data_security

_TENANT = "tenant-xcloud-ai"
_ACCOUNT = "acmestorage"
_SSN = b"patient ssn 123-45-6789 on file\n"


@pytest.mark.asyncio
async def test_azure_exposed_openai_with_sensitive_training_data_lights_up() -> None:
    async with in_memory_semantic_store() as store:
        containers = (AzureContainer("training", public_access="container", blobs={"d.csv": _SSN}),)
        await drive_azure_data_security(
            store, tenant_id=_TENANT, containers=containers, storage_account=_ACCOUNT
        )
        await drive_azure_aispm(
            store,
            tenant_id=_TENANT,
            accounts=(
                AzureOpenAiSeed(
                    "gpt", public=True, model_data_account=_ACCOUNT, model_data_container="training"
                ),
            ),
        )
        hits = await KgQuery(store, _TENANT).find_exposed_ai_with_sensitive_data()
        assert len(hits) == 1
        assert hits[0].data_type == "ssn"


@pytest.mark.asyncio
async def test_azure_private_training_data_is_dark() -> None:
    async with in_memory_semantic_store() as store:
        # The training container is PRIVATE → no EXPOSES_DATA → no path-10 hit.
        containers = (AzureContainer("training", public_access="none", blobs={"d.csv": _SSN}),)
        await drive_azure_data_security(
            store, tenant_id=_TENANT, containers=containers, storage_account=_ACCOUNT
        )
        await drive_azure_aispm(
            store,
            tenant_id=_TENANT,
            accounts=(
                AzureOpenAiSeed(
                    "gpt", public=True, model_data_account=_ACCOUNT, model_data_container="training"
                ),
            ),
        )
        assert await KgQuery(store, _TENANT).find_exposed_ai_with_sensitive_data() == []


@pytest.mark.asyncio
async def test_gcp_exposed_vertex_with_sensitive_training_data_lights_up() -> None:
    async with in_memory_semantic_store() as store:
        buckets = (GcsBucketSeed("training", iam_members=(PUBLIC_MEMBER,), blobs={"d.csv": _SSN}),)
        await drive_gcs_data_security(store, tenant_id=_TENANT, buckets=buckets)
        await drive_gcp_aispm(
            store,
            tenant_id=_TENANT,
            endpoints=(VertexEndpointSeed("llm", public=True, model_data_bucket="training"),),
        )
        hits = await KgQuery(store, _TENANT).find_exposed_ai_with_sensitive_data()
        assert len(hits) == 1
        assert hits[0].data_type == "ssn"


@pytest.mark.asyncio
async def test_gcp_non_public_endpoint_is_dark() -> None:
    async with in_memory_semantic_store() as store:
        buckets = (GcsBucketSeed("training", iam_members=(PUBLIC_MEMBER,), blobs={"d.csv": _SSN}),)
        await drive_gcs_data_security(store, tenant_id=_TENANT, buckets=buckets)
        # The endpoint is NOT public → no EXPOSES_MODEL → no path-10 hit (data is exposed, model isn't).
        await drive_gcp_aispm(
            store,
            tenant_id=_TENANT,
            endpoints=(VertexEndpointSeed("llm", public=False, model_data_bucket="training"),),
        )
        assert await KgQuery(store, _TENANT).find_exposed_ai_with_sensitive_data() == []
