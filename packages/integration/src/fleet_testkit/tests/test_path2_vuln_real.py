"""Path 2 slice 2a — vulnerability is a REAL feeder (real Trivy → CVE graph).

Proves vulnerability's overlay REAL through its own code: a fixture with a genuinely
vulnerable package (Django 2.0.0) is scanned by the **real** ``trivy fs`` binary, and the
**real** ``record_scan_results`` writes the artifact ``CLOUD_RESOURCE`` + ``CVE_FINDING``
nodes + ``VULNERABLE_TO`` edges. No hand-faked findings — a real scanner, real CVE DB,
real vulnerable package. Trivy-gated (not hermetic like moto): skips where Trivy is absent.
"""

from pathlib import Path

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.vuln_scan import drive_vulnerability, trivy_available

pytestmark = pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")

_TENANT = "tenant-path2a"
_IMAGE_REF = "myreg/app:1.0"


def _write_vulnerable_fixture(root: Path) -> None:
    # Django 2.0.0 carries multiple real CRITICAL CVEs in Trivy's DB (e.g. CVE-2019-19844).
    (root / "requirements.txt").write_text("Django==2.0.0\n")


@pytest.mark.asyncio
async def test_real_trivy_scan_writes_cve_graph(tmp_path: Path) -> None:
    _write_vulnerable_fixture(tmp_path)
    async with in_memory_semantic_store() as store:
        ref = await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_IMAGE_REF
        )
        assert ref == _IMAGE_REF

        # The artifact is recorded under the image ref (the bridge key), not the fs path.
        resources = await store.list_entities_by_type(
            tenant_id=_TENANT, entity_type=NodeCategory.CLOUD_RESOURCE.value
        )
        artifact = next((r for r in resources if r.external_id == _IMAGE_REF), None)
        assert artifact is not None, "scanned image artifact node written under image ref"

        # Real CVEs landed as CVE_FINDING nodes, joined by VULNERABLE_TO.
        cves = await store.list_entities_by_type(
            tenant_id=_TENANT, entity_type=NodeCategory.CVE_FINDING.value
        )
        assert cves, "real trivy scan produced at least one CVE_FINDING node"
        edges = await store.get_relationships_from(
            tenant_id=_TENANT,
            src_entity_id=artifact.entity_id,
            edge_types=(EdgeType.VULNERABLE_TO.value,),
        )
        assert len(edges) == len(cves), "every CVE is joined to the artifact via VULNERABLE_TO"


@pytest.mark.asyncio
async def test_clean_fixture_writes_no_cves(tmp_path: Path) -> None:
    # A package with no known HIGH/CRITICAL CVEs → real trivy finds nothing → empty overlay.
    (tmp_path / "requirements.txt").write_text("certifi==2024.2.2\n")
    async with in_memory_semantic_store() as store:
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref="myreg/clean:1.0"
        )
        cves = await store.list_entities_by_type(
            tenant_id=_TENANT, entity_type=NodeCategory.CVE_FINDING.value
        )
        assert cves == []
