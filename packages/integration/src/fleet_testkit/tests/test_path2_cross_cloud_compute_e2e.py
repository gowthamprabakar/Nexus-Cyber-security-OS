"""Cross-cloud path 2 (gap #13) — internet-exposed Azure ACI / GCP Cloud Run + vulnerable image, REAL e2e.

Mirror of the AWS path-2 e2e on the mechanism-② image-ref bridge, per cloud:
- cloud-posture's REAL ACI / Cloud Run reader + writer writes a public workload + ``RUNS_IMAGE`` →
  image ``myreg/app:1.0`` (hermetic — in-memory injectable client).
- vulnerability's REAL ``record_scan_results`` writes CVEs from a REAL ``trivy fs`` scan onto the
  SAME ``myreg/app:1.0`` image node (trivy-gated).
- ``find_internet_exposed_vulnerable_workload`` lights up the exposed-workload → CVE path; a private
  workload stays dark.
"""

import pytest
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.cross_cloud_compute import (
    AciGroup,
    CloudRunService,
    drive_azure_compute,
    drive_gcp_compute,
)
from fleet_testkit.vuln_scan import drive_vulnerability, trivy_available

pytestmark = pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")

_TENANT = "tenant-azure-compute"
_IMAGE_REF = "myreg/app:1.0"


def _write_vulnerable_fixture(root) -> None:
    (root / "requirements.txt").write_text("Django==2.0.0\n")


@pytest.mark.asyncio
async def test_exposed_azure_workload_running_vulnerable_image_lights_up(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    async with in_memory_semantic_store() as store:
        groups = (AciGroup("web", image=_IMAGE_REF, public=True),)
        await drive_azure_compute(store, tenant_id=_TENANT, groups=groups)
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_IMAGE_REF
        )
        hits = await KgQuery(store, _TENANT).find_internet_exposed_vulnerable_workload()
        assert hits, "exposed Azure ACI running a vulnerable image surfaces a path-2 hit"
        assert all(h.image_id for h in hits)
        assert all(h.cve_id for h in hits)


@pytest.mark.asyncio
async def test_private_azure_workload_with_vulnerable_image_is_dark(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    async with in_memory_semantic_store() as store:
        groups = (AciGroup("web", image=_IMAGE_REF, public=False),)
        await drive_azure_compute(store, tenant_id=_TENANT, groups=groups)
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_IMAGE_REF
        )
        assert await KgQuery(store, _TENANT).find_internet_exposed_vulnerable_workload() == []


@pytest.mark.asyncio
async def test_exposed_gcp_workload_running_vulnerable_image_lights_up(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    async with in_memory_semantic_store() as store:
        services = (CloudRunService("web", image=_IMAGE_REF, public=True),)
        await drive_gcp_compute(store, tenant_id=_TENANT, services=services)
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_IMAGE_REF
        )
        hits = await KgQuery(store, _TENANT).find_internet_exposed_vulnerable_workload()
        assert hits, "public Cloud Run service running a vulnerable image surfaces a path-2 hit"
        assert all(h.cve_id for h in hits)


@pytest.mark.asyncio
async def test_private_gcp_workload_with_vulnerable_image_is_dark(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    async with in_memory_semantic_store() as store:
        services = (CloudRunService("web", image=_IMAGE_REF, public=False),)
        await drive_gcp_compute(store, tenant_id=_TENANT, services=services)
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=_IMAGE_REF
        )
        assert await KgQuery(store, _TENANT).find_internet_exposed_vulnerable_workload() == []
