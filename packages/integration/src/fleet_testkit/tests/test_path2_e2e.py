"""Path 2 (internet-exposed workload + KEV vuln) committed e2e — the full REAL chain.

Ties both feeders into ONE attack path through their own code, joined by the mechanism-②
bridge (the image ref node both sides key on):

- cloud-posture's *real* ECS reader + ``record_workloads`` write an internet-exposed
  workload (moto ECS service + real 0.0.0.0/0 SG) + ``RUNS_IMAGE`` → image ``myreg/app:1.0``.
- vulnerability's *real* ``record_scan_results`` writes CVEs from a *real* ``trivy fs`` scan
  of a genuinely-vulnerable package, recorded onto the SAME ``myreg/app:1.0`` image node.
- ``KgQuery.find_internet_exposed_vulnerable_workload`` lights up the exposed-workload→CVE path.

The ECS/exposure leg is hermetic (moto, in-process); the vuln leg is trivy-gated (real
binary). No hand-faked findings on either side.
"""

import pytest
from charter.memory.graph_types import NodeCategory
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.moto_aws import (
    drive_cloud_workloads,
    moto_ecs_clients,
    setup_ecs_workload,
)
from fleet_testkit.vuln_scan import drive_vulnerability, trivy_available

pytestmark = pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")

_TENANT = "tenant-path2e2e"
_IMAGE_REF = "myreg/app:1.0"


def _write_vulnerable_fixture(root) -> None:
    (root / "requirements.txt").write_text("Django==2.0.0\n")


@pytest.mark.asyncio
async def test_exposed_workload_running_vulnerable_image_lights_up(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    async with in_memory_semantic_store() as store:
        # Leg 1 — exposed workload + RUNS_IMAGE bridge (real cloud-posture, moto ECS).
        with moto_ecs_clients() as (ecs, ec2):
            setup_ecs_workload(ecs, ec2, image_ref=_IMAGE_REF, public=True)
            await drive_cloud_workloads(store, tenant_id=_TENANT, ecs_client=ecs, ec2_client=ec2)
        # Leg 2 — CVEs on the SAME image node (real vulnerability, real trivy).
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_IMAGE_REF
        )

        hits = await KgQuery(store, _TENANT).find_internet_exposed_vulnerable_workload()
        assert hits, "exposed workload running a vulnerable image surfaces a path-2 hit"
        assert all(h.image_id for h in hits)
        # Every hit carries a real CVE id from the trivy scan.
        assert all(h.cve_id.startswith("CVE-") for h in hits)


@pytest.mark.asyncio
async def test_private_workload_with_vulnerable_image_is_dark(tmp_path) -> None:
    # Same vulnerable image, but a non-exposed workload → no path-2 hit.
    _write_vulnerable_fixture(tmp_path)
    async with in_memory_semantic_store() as store:
        with moto_ecs_clients() as (ecs, ec2):
            setup_ecs_workload(ecs, ec2, image_ref=_IMAGE_REF, public=False)
            await drive_cloud_workloads(store, tenant_id=_TENANT, ecs_client=ecs, ec2_client=ec2)
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_IMAGE_REF
        )
        # Sanity: the CVEs ARE on the graph; only the exposure leg is missing.
        cves = await store.list_entities_by_type(
            tenant_id=_TENANT, entity_type=NodeCategory.CVE_FINDING.value
        )
        assert cves
        assert await KgQuery(store, _TENANT).find_internet_exposed_vulnerable_workload() == []
