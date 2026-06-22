"""Path 5: find_crown_jewel_exposure — the 4-hop crown jewel. An internet-exposed
workload (is_public) that RUNS_IMAGE a VULNERABLE_TO image AND ASSUMES a role with
HAS_ACCESS_TO a resource that EXPOSES_DATA. Read-only."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import KgQuery


async def _edge(store, tenant, src, dst, rel):
    await store.add_relationship(
        tenant_id=tenant, src_entity_id=src, dst_entity_id=dst, relationship_type=rel, properties={}
    )


async def _node(store, tenant, etype, ext, props):
    return await store.upsert_entity(
        tenant_id=tenant, entity_type=etype, external_id=ext, properties=props
    )


async def _seed(store, *, tenant, is_public=True, with_cve=True, with_access=True):
    R = NodeCategory.CLOUD_RESOURCE.value
    workload = await _node(
        store, tenant, R, "arn:ecs:svc/web", {"kind": "ecs-service", "is_public": is_public}
    )
    image = await _node(store, tenant, R, "myreg/app:1.0", {"kind": "container-image"})
    role = await _node(store, tenant, NodeCategory.IDENTITY.value, "arn:iam:role/task", {})
    bucket = await _node(store, tenant, R, "arn:aws:s3:::secret", {"is_public": True})
    dc = await _node(
        store,
        tenant,
        NodeCategory.DATA_CLASSIFICATION.value,
        "arn:aws:s3:::secret:ssn",
        {"data_type": "ssn"},
    )
    await _edge(store, tenant, workload, image, EdgeType.RUNS_IMAGE.value)
    await _edge(store, tenant, workload, role, EdgeType.ASSUMES.value)
    await _edge(store, tenant, bucket, dc, EdgeType.EXPOSES_DATA.value)
    if with_cve:
        cve = await _node(
            store,
            tenant,
            NodeCategory.CVE_FINDING.value,
            "CVE-2019-19844",
            {"severity": "CRITICAL"},
        )
        await _edge(store, tenant, image, cve, EdgeType.VULNERABLE_TO.value)
    if with_access:
        await _edge(store, tenant, role, bucket, EdgeType.HAS_ACCESS_TO.value)
    return {"workload": workload, "image": image, "role": role, "bucket": bucket, "dc": dc}


@pytest.mark.asyncio
async def test_detects_full_crown_jewel():
    async with in_memory_semantic_store() as store:
        ids = await _seed(store, tenant="t")
        hits = await KgQuery(store, "t").find_crown_jewel_exposure()
        assert len(hits) == 1
        h = hits[0]
        assert h.workload_id == ids["workload"]
        assert h.image_id == ids["image"]
        assert h.cve_id == "CVE-2019-19844"
        assert h.role_id == ids["role"]
        assert h.resource_id == ids["bucket"]
        assert h.data_type == "ssn"


@pytest.mark.asyncio
async def test_not_exposed_is_dark():
    async with in_memory_semantic_store() as store:
        await _seed(store, tenant="t", is_public=False)
        assert await KgQuery(store, "t").find_crown_jewel_exposure() == []


@pytest.mark.asyncio
async def test_no_vulnerability_is_dark():
    # Exposed + role-reaches-data, but the image is clean → not the crown jewel.
    async with in_memory_semantic_store() as store:
        await _seed(store, tenant="t", with_cve=False)
        assert await KgQuery(store, "t").find_crown_jewel_exposure() == []


@pytest.mark.asyncio
async def test_role_without_data_access_is_dark():
    # Exposed + vulnerable, but the task role can't reach the sensitive data → not crown jewel.
    async with in_memory_semantic_store() as store:
        await _seed(store, tenant="t", with_access=False)
        assert await KgQuery(store, "t").find_crown_jewel_exposure() == []
