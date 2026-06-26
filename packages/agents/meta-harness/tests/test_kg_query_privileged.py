"""Path 6: find_privileged_vulnerable_workload — a privileged K8s pod that RUNS_IMAGE a
VULNERABLE_TO image. Read-only."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import KgQuery


async def _seed(store, *, tenant, privileged=True, with_cve=True):
    pod = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.K8S_OBJECT.value,
        external_id="kind/namespace/default/pod/web",
        properties={"kind": "pod", "privileged": privileged},
    )
    image = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id="myreg/app:1.0",
        properties={"kind": "container-image"},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=pod,
        dst_entity_id=image,
        relationship_type=EdgeType.RUNS_IMAGE.value,
        properties={},
    )
    if with_cve:
        cve = await store.upsert_entity(
            tenant_id=tenant,
            entity_type=NodeCategory.CVE_FINDING.value,
            external_id="CVE-2019-19844",
            properties={"severity": "CRITICAL"},
        )
        await store.add_relationship(
            tenant_id=tenant,
            src_entity_id=image,
            dst_entity_id=cve,
            relationship_type=EdgeType.VULNERABLE_TO.value,
            properties={},
        )
    return pod, image


@pytest.mark.asyncio
async def test_detects_privileged_vulnerable_pod():
    async with in_memory_semantic_store() as store:
        pod, image = await _seed(store, tenant="t")
        hits = await KgQuery(store, "t").find_privileged_vulnerable_workload()
        assert len(hits) == 1
        assert hits[0].workload_id == pod
        assert hits[0].image_id == image
        assert hits[0].cve_id == "CVE-2019-19844"
        assert hits[0].severity == "CRITICAL"


@pytest.mark.asyncio
async def test_non_privileged_pod_is_dark():
    async with in_memory_semantic_store() as store:
        await _seed(store, tenant="t", privileged=False)
        assert await KgQuery(store, "t").find_privileged_vulnerable_workload() == []


@pytest.mark.asyncio
async def test_privileged_but_clean_image_is_dark():
    async with in_memory_semantic_store() as store:
        await _seed(store, tenant="t", with_cve=False)
        assert await KgQuery(store, "t").find_privileged_vulnerable_workload() == []
