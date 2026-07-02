"""NEX-305 e2e — SBOM supply-chain: a public workload runs an image with a vulnerable dependency.

Unlike image-level vuln (workload → image → CVE), this names the specific vulnerable PACKAGE
(Log4Shell shape). Drives the REAL vulnerability writer (record_sbom_packages) and proves the walk:
``public workload --RUNS_IMAGE--> image --CONTAINS_PACKAGE--> package --VULNERABLE_TO--> CVE``.
"""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from meta_harness.coverage import measure_coverage
from meta_harness.path_engine import find_candidate_paths
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

        cands = await find_candidate_paths(store, _T)
        sbom = [c for c in cands if "CONTAINS_PACKAGE" in c.path.edge_signature]
        assert sbom, "a supply-chain (SBOM dependency) vuln path must surface"
        assert sbom[0].path.edge_signature == ("RUNS_IMAGE", "CONTAINS_PACKAGE", "VULNERABLE_TO")
        assert "supply_chain_sbom" in (await measure_coverage(store, _T)).produced
