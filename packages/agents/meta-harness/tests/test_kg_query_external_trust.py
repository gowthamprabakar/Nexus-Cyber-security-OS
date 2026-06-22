"""Path 8: find_external_trust_exposure — an externally-trusted principal (cross-account
trust) that HAS_ACCESS_TO a public resource EXPOSING sensitive data. Read-only."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import KgQuery


async def _seed(store, *, tenant, role_arn, external_trust, bucket_arn, edge):
    role = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.IDENTITY.value,
        external_id=role_arn,
        properties={"principal_type": "role", "external_trust": external_trust},
    )
    bucket = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id=bucket_arn,
        properties={"is_public": True},
    )
    dc = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.DATA_CLASSIFICATION.value,
        external_id=f"{bucket_arn}:ssn",
        properties={"data_type": "ssn"},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=role,
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
    return role, bucket, dc


@pytest.mark.asyncio
async def test_detects_external_trust_exposure():
    async with in_memory_semantic_store() as store:
        role, bucket, dc = await _seed(
            store,
            tenant="t",
            role_arn="arn:aws:iam::111111111111:role/cross-acct",
            external_trust=True,
            bucket_arn="arn:aws:s3:::open-pii",
            edge=EdgeType.EXPOSES_DATA.value,
        )
        hits = await KgQuery(store, "t").find_external_trust_exposure()
        assert len(hits) == 1
        assert hits[0].principal_id == role
        assert hits[0].resource_id == bucket
        assert hits[0].data_classification_id == dc
        assert hits[0].data_type == "ssn"


@pytest.mark.asyncio
async def test_internal_only_principal_is_dark():
    # Not externally trusted → no path-8 hit even with access to public sensitive data.
    async with in_memory_semantic_store() as store:
        await _seed(
            store,
            tenant="t",
            role_arn="arn:aws:iam::111111111111:role/internal",
            external_trust=False,
            bucket_arn="arn:aws:s3:::open-pii",
            edge=EdgeType.EXPOSES_DATA.value,
        )
        assert await KgQuery(store, "t").find_external_trust_exposure() == []


@pytest.mark.asyncio
async def test_private_resource_is_dark():
    # External trust + access, but a private bucket (CONTAINS, no EXPOSES_DATA) → dark.
    async with in_memory_semantic_store() as store:
        await _seed(
            store,
            tenant="t",
            role_arn="arn:aws:iam::111111111111:role/cross-acct",
            external_trust=True,
            bucket_arn="arn:aws:s3:::priv-pii",
            edge=EdgeType.CONTAINS.value,
        )
        assert await KgQuery(store, "t").find_external_trust_exposure() == []
