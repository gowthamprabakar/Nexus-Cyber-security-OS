"""Path 10: find_exposed_ai_with_sensitive_data — an internet-exposed AI service
(EXPOSES_MODEL → internet) that HAS_ACCESS_TO a bucket EXPOSES_DATA. Read-only."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import KgQuery


async def _seed(store, *, tenant, exposed=True, with_access=True):
    svc = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.AI_SERVICE.value,
        external_id="aws:111:sagemaker:e",
        properties={"kind": "endpoint"},
    )
    internet = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id="internet",
        properties={"kind": "internet"},
    )
    bucket = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id="arn:aws:s3:::train",
        properties={"is_public": True},
    )
    dc = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.DATA_CLASSIFICATION.value,
        external_id="arn:aws:s3:::train:ssn",
        properties={"data_type": "ssn"},
    )
    if exposed:
        await store.add_relationship(
            tenant_id=tenant,
            src_entity_id=svc,
            dst_entity_id=internet,
            relationship_type=EdgeType.EXPOSES_MODEL.value,
            properties={},
        )
    if with_access:
        await store.add_relationship(
            tenant_id=tenant,
            src_entity_id=svc,
            dst_entity_id=bucket,
            relationship_type=EdgeType.HAS_ACCESS_TO.value,
            properties={},
        )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=bucket,
        dst_entity_id=dc,
        relationship_type=EdgeType.EXPOSES_DATA.value,
        properties={},
    )
    return svc, bucket


@pytest.mark.asyncio
async def test_detects_exposed_ai_with_sensitive_training_data():
    async with in_memory_semantic_store() as store:
        svc, bucket = await _seed(store, tenant="t")
        hits = await KgQuery(store, "t").find_exposed_ai_with_sensitive_data()
        assert len(hits) == 1
        assert hits[0].service_id == svc
        assert hits[0].resource_id == bucket
        assert hits[0].data_type == "ssn"


@pytest.mark.asyncio
async def test_network_isolated_ai_is_dark():
    async with in_memory_semantic_store() as store:
        await _seed(store, tenant="t", exposed=False)
        assert await KgQuery(store, "t").find_exposed_ai_with_sensitive_data() == []


@pytest.mark.asyncio
async def test_exposed_ai_without_data_access_is_dark():
    async with in_memory_semantic_store() as store:
        await _seed(store, tenant="t", with_access=False)
        assert await KgQuery(store, "t").find_exposed_ai_with_sensitive_data() == []
