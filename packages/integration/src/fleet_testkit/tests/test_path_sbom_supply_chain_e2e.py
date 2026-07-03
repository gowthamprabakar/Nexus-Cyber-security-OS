"""NEX-305 e2e — SBOM supply-chain: a public workload runs an image with a vulnerable dependency.

Unlike image-level vuln (workload → image → CVE), this names the specific vulnerable PACKAGE
(Log4Shell shape). Drives the REAL vulnerability writer (record_sbom_packages) and proves the walk:
``public workload --RUNS_IMAGE--> image --CONTAINS_PACKAGE--> package --VULNERABLE_TO--> CVE``.
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from meta_harness.coverage import measure_coverage
from meta_harness.kg_query import KgQuery
from vulnerability.kg_writer import KnowledgeGraphWriter as VulnKgWriter

from fleet_testkit import in_memory_semantic_store

_T = "sbom"
_WORKLOAD = "arn:aws:ecs:us-east-1:1:service/web"
_IMAGE = "myreg/app:1.0"


@pytest.mark.asyncio
async def test_sbom_dependency_vuln_path_emerges() -> None:
    async with in_memory_semantic_store() as store:
        # public workload runs the image
        wl = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_WORKLOAD,
            properties={"is_public": True},
        )
        img = await store.upsert_entity(
            tenant_id=_T,
            entity_type=NodeCategory.CLOUD_RESOURCE.value,
            external_id=_IMAGE,
            properties={"kind": "container-image"},
        )
        await store.add_relationship(
            tenant_id=_T,
            src_entity_id=wl,
            dst_entity_id=img,
            relationship_type=EdgeType.RUNS_IMAGE.value,
            properties={},
        )
        # the image's SBOM: log4j is the vulnerable dependency (real writer)
        await VulnKgWriter(store, _T).record_sbom_packages(
            _IMAGE, [("log4j-core", "CVE-2021-44228", "CRITICAL")]
        )

        hits = await KgQuery(store, _T).find_sbom_vulnerable_workload()
        assert hits, "a supply-chain (SBOM dependency) vuln path must surface"
        assert hits[0].workload_id  # the public workload
        assert hits[0].image_id  # the image it runs
        assert hits[0].package_id  # the named vulnerable package
        assert hits[0].cve_id == "CVE-2021-44228"
        assert hits[0].severity == "CRITICAL"
        assert "supply_chain_sbom" in (await measure_coverage(store, _T)).produced
