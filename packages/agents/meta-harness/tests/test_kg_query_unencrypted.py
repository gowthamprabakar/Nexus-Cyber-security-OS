"""Path 7: find_public_unencrypted_exposure — a public resource that EXPOSES_DATA
sensitive data AND is unencrypted at rest (exposure + compliance failure). Read-only."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import KgQuery


async def _seed(store, *, tenant, arn, is_encrypted, data_type, edge):
    bucket = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id=arn,
        properties={"is_public": True, "is_encrypted": is_encrypted},
    )
    dc = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.DATA_CLASSIFICATION.value,
        external_id=f"{arn}:{data_type}",
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
async def test_detects_public_unencrypted_exposure():
    async with in_memory_semantic_store() as store:
        bucket, dc = await _seed(
            store,
            tenant="t",
            arn="arn:aws:s3:::open-clear",
            is_encrypted=False,
            data_type="ssn",
            edge=EdgeType.EXPOSES_DATA.value,
        )
        hits = await KgQuery(store, "t").find_public_unencrypted_exposure()
        assert len(hits) == 1
        assert hits[0].resource_id == bucket
        assert hits[0].data_classification_id == dc
        assert hits[0].data_type == "ssn"


@pytest.mark.asyncio
async def test_encrypted_resource_is_dark():
    # Encrypted at rest → not a compliance failure on this axis, even if public+sensitive.
    async with in_memory_semantic_store() as store:
        await _seed(
            store,
            tenant="t",
            arn="arn:aws:s3:::open-enc",
            is_encrypted=True,
            data_type="ssn",
            edge=EdgeType.EXPOSES_DATA.value,
        )
        assert await KgQuery(store, "t").find_public_unencrypted_exposure() == []


@pytest.mark.asyncio
async def test_non_public_unencrypted_is_dark():
    # Private bucket: CONTAINS but no EXPOSES_DATA → not publicly exposed.
    async with in_memory_semantic_store() as store:
        await _seed(
            store,
            tenant="t",
            arn="arn:aws:s3:::priv-clear",
            is_encrypted=False,
            data_type="ssn",
            edge=EdgeType.CONTAINS.value,
        )
        assert await KgQuery(store, "t").find_public_unencrypted_exposure() == []
