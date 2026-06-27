"""Path 3: find_public_secret_exposure — a public resource that EXPOSES_DATA a
secret-type classification (a publicly-readable credential). Read-only (ADR-023)."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import KgQuery


async def _seed(store, *, tenant, bucket_arn, data_type, edge):
    bucket = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id=bucket_arn,
        properties={},
    )
    dc = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.DATA_CLASSIFICATION.value,
        external_id=f"{bucket_arn}:{data_type}",
        properties={"data_type": data_type},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=bucket,
        dst_entity_id=dc,
        relationship_type=edge,
        properties={},
    )
    return bucket, dc


@pytest.mark.asyncio
async def test_detects_public_secret_exposure():
    async with in_memory_semantic_store() as store:
        bucket, dc = await _seed(
            store,
            tenant="t",
            bucket_arn="arn:aws:s3:::creds",
            data_type="aws_access_key",
            edge=EdgeType.EXPOSES_DATA.value,
        )
        hits = await KgQuery(store, "t").find_public_secret_exposure()
        assert len(hits) == 1
        assert hits[0].resource_id == bucket
        assert hits[0].data_classification_id == dc
        assert hits[0].data_type == "aws_access_key"


@pytest.mark.asyncio
async def test_ignores_pii_data_type():
    # PII (ssn) exposed publicly is path 1's concern, not a secret — must NOT match here.
    async with in_memory_semantic_store() as store:
        await _seed(
            store,
            tenant="t",
            bucket_arn="arn:aws:s3:::pii",
            data_type="ssn",
            edge=EdgeType.EXPOSES_DATA.value,
        )
        assert await KgQuery(store, "t").find_public_secret_exposure() == []


@pytest.mark.asyncio
async def test_ignores_non_public_secret():
    # Private bucket: CONTAINS but no EXPOSES_DATA → a secret at rest, not publicly exposed.
    async with in_memory_semantic_store() as store:
        await _seed(
            store,
            tenant="t",
            bucket_arn="arn:aws:s3:::priv",
            data_type="aws_access_key",
            edge=EdgeType.CONTAINS.value,
        )
        assert await KgQuery(store, "t").find_public_secret_exposure() == []
