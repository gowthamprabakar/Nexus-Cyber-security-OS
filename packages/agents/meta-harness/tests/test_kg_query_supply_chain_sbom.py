"""find_supply_chain_sbom: public workload → image → SBOM_PACKAGE → CVE (NEX-305)."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import KgQuery

_T = "t-sbom"


async def _seed(
    store,
    *,
    tenant: str,
    is_public: bool,
    pkg_name: str = "log4j-core",
    cve_id: str = "CVE-2021-44228",
    severity: str = "CRITICAL",
) -> tuple[str, str, str, str]:
    """Seed: workload --RUNS_IMAGE--> image --CONTAINS_PACKAGE--> pkg --VULNERABLE_TO--> cve."""
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
    pkg = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.SBOM_PACKAGE.value,
        external_id=f"myreg/app:1.0#{pkg_name}",
        properties={"name": pkg_name},
    )
    cve = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CVE_FINDING.value,
        external_id=cve_id,
        properties={"severity": severity},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=workload,
        dst_entity_id=image,
        relationship_type=EdgeType.RUNS_IMAGE.value,
        properties={},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=image,
        dst_entity_id=pkg,
        relationship_type=EdgeType.CONTAINS_PACKAGE.value,
        properties={},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=pkg,
        dst_entity_id=cve,
        relationship_type=EdgeType.VULNERABLE_TO.value,
        properties={},
    )
    return workload, image, pkg, cve


@pytest.mark.asyncio
async def test_detects_sbom_supply_chain_path():
    """Public workload → image → package → CVE yields one SupplyChainSbom hit."""
    async with in_memory_semantic_store() as store:
        workload, image, _pkg, _cve = await _seed(store, tenant=_T, is_public=True)
        hits = await KgQuery(store, _T).find_supply_chain_sbom()
        assert len(hits) == 1
        hit = hits[0]
        assert hit.workload_id == workload
        assert hit.image_id == image
        assert hit.package_name == "log4j-core"
        assert hit.cve_id == "CVE-2021-44228"
        assert hit.severity == "CRITICAL"
        assert hit.kev_listed is False
        assert hit.epss_score is None


@pytest.mark.asyncio
async def test_private_workload_is_dark():
    """Private workload with SBOM path yields no hit (is_public gate)."""
    async with in_memory_semantic_store() as store:
        await _seed(store, tenant=_T, is_public=False)
        assert await KgQuery(store, _T).find_supply_chain_sbom() == []


@pytest.mark.asyncio
async def test_image_vuln_without_sbom_package_is_dark():
    """Image-level CVE without CONTAINS_PACKAGE hop yields no supply_chain_sbom hit."""
    async with in_memory_semantic_store() as store:
        workload = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="arn:aws:ecs:us-east-1:111:service/c/plain",
            properties={"kind": "ecs-service", "is_public": True},
        )
        image = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id="myreg/plain:1.0",
            properties={"kind": "container-image"},
        )
        cve = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CVE_FINDING.value,
            external_id="CVE-2019-19844",
            properties={"severity": "HIGH"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=workload,
            dst_entity_id=image,
            relationship_type=EdgeType.RUNS_IMAGE.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=image,
            dst_entity_id=cve,
            relationship_type=EdgeType.VULNERABLE_TO.value,
            properties={},
        )
        # VULNERABLE_TO hangs off image directly — no CONTAINS_PACKAGE hop
        assert await KgQuery(store, _T).find_supply_chain_sbom() == []
