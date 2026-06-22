"""Path 2: find_internet_exposed_vulnerable_workload — an internet-exposed workload
(is_public) running an image (RUNS_IMAGE) with a known CVE (VULNERABLE_TO). Read-only."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import KgQuery


async def _seed(store, *, tenant, is_public, severity="CRITICAL", with_cve=True):
    workload = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id="arn:aws:ecs:us-east-1:111:service/c/web",
        properties={"kind": "ecs-service", "is_public": is_public},
    )
    image = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id="myreg/app:1.0",
        properties={"kind": "container-image"},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=workload,
        dst_entity_id=image,
        relationship_type=EdgeType.RUNS_IMAGE.value,
        properties={},
    )
    cve = None
    if with_cve:
        cve = await store.upsert_entity(
            tenant_id=tenant,
            entity_type=NodeCategory.CVE_FINDING.value,
            external_id="CVE-2019-19844",
            properties={"severity": severity},
        )
        await store.add_relationship(
            tenant_id=tenant,
            src_entity_id=image,
            dst_entity_id=cve,
            relationship_type=EdgeType.VULNERABLE_TO.value,
            properties={},
        )
    return workload, image, cve


@pytest.mark.asyncio
async def test_detects_exposed_vulnerable_workload():
    async with in_memory_semantic_store() as store:
        workload, image, _cve = await _seed(store, tenant="t", is_public=True)
        hits = await KgQuery(store, "t").find_internet_exposed_vulnerable_workload()
        assert len(hits) == 1
        assert hits[0].workload_id == workload
        assert hits[0].image_id == image
        assert hits[0].cve_id == "CVE-2019-19844"
        assert hits[0].severity == "CRITICAL"


@pytest.mark.asyncio
async def test_private_workload_is_dark():
    # Same vulnerable image, but the workload is NOT internet-exposed → no path-2 hit.
    async with in_memory_semantic_store() as store:
        await _seed(store, tenant="t", is_public=False)
        assert await KgQuery(store, "t").find_internet_exposed_vulnerable_workload() == []


@pytest.mark.asyncio
async def test_exposed_but_no_cve_is_dark():
    # Exposed workload running a clean image (no VULNERABLE_TO) → dark.
    async with in_memory_semantic_store() as store:
        await _seed(store, tenant="t", is_public=True, with_cve=False)
        assert await KgQuery(store, "t").find_internet_exposed_vulnerable_workload() == []
