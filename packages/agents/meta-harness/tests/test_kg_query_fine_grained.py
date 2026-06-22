"""Path 4: find_fine_grained_data_exposure — a principal with a concrete (non-admin)
HAS_ACCESS_TO grant to a public resource that EXPOSES_DATA sensitive data. Read-only."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import KgQuery


async def _seed(store, *, tenant, with_access=True, edge=None):
    edge = edge or EdgeType.EXPOSES_DATA.value
    principal = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.IDENTITY.value,
        external_id="arn:aws:iam::111:role/reader",
        properties={"principal_type": "role"},
    )
    bucket = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id="arn:aws:s3:::secret",
        properties={"is_public": True},
    )
    dc = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.DATA_CLASSIFICATION.value,
        external_id="arn:aws:s3:::secret:ssn",
        properties={"data_type": "ssn"},
    )
    if with_access:
        await store.add_relationship(
            tenant_id=tenant,
            src_entity_id=principal,
            dst_entity_id=bucket,
            relationship_type=EdgeType.HAS_ACCESS_TO.value,
            properties={},
        )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=bucket,
        dst_entity_id=dc,
        relationship_type=edge,
        properties={},
    )
    return principal, bucket, dc


@pytest.mark.asyncio
async def test_detects_fine_grained_exposure():
    async with in_memory_semantic_store() as store:
        principal, bucket, dc = await _seed(store, tenant="t")
        hits = await KgQuery(store, "t").find_fine_grained_data_exposure()
        assert len(hits) == 1
        assert hits[0].principal_id == principal
        assert hits[0].resource_id == bucket
        assert hits[0].data_classification_id == dc
        assert hits[0].data_type == "ssn"


@pytest.mark.asyncio
async def test_no_access_edge_is_dark():
    # Sensitive public bucket, but the principal has no HAS_ACCESS_TO → no exposure.
    async with in_memory_semantic_store() as store:
        await _seed(store, tenant="t", with_access=False)
        assert await KgQuery(store, "t").find_fine_grained_data_exposure() == []


@pytest.mark.asyncio
async def test_private_resource_is_dark():
    # Access to a private bucket (CONTAINS, no EXPOSES_DATA) → not publicly exposed.
    async with in_memory_semantic_store() as store:
        await _seed(store, tenant="t", edge=EdgeType.CONTAINS.value)
        assert await KgQuery(store, "t").find_fine_grained_data_exposure() == []
