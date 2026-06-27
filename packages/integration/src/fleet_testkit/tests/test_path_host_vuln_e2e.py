"""Path #15 — internet-exposed host (EC2/VM) with an OS-package CVE, REAL e2e.

Ties two real feeders into one host-vuln path through their own code:

- cloud-posture's *real* EC2 reader + ``record_ec2_workloads`` write a public instance node.
- vulnerability's *real* ``record_scan_results`` writes CVEs from a *real* ``trivy fs`` scan,
  relabeled onto the SAME instance-ARN node (production parity: ``trivy vm/rootfs`` names the
  host scan after the instance it ran on — the host analogue of the image-ref relabel).
- ``KgQuery.find_internet_exposed_host_vulnerable`` lights up the exposed-host→CVE path.

The EC2/exposure leg is hermetic (moto); the vuln leg is trivy-gated (real binary). No hand-faked
findings — the CVE is detected by real Trivy in a real vulnerable package.
"""

import pytest
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.moto_aws import drive_ec2_workloads, moto_full_clients, setup_ec2_instance
from fleet_testkit.vuln_scan import drive_vulnerability, trivy_available

pytestmark = pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")

_TENANT = "tenant-hostvuln"


def _write_vulnerable_fixture(root) -> None:
    (root / "requirements.txt").write_text("Django==2.0.0\n")


@pytest.mark.asyncio
async def test_exposed_host_with_os_vuln_lights_up(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    async with in_memory_semantic_store() as store:
        with moto_full_clients(()) as (_s3, iam, _ecs, ec2, _sm):
            setup_ec2_instance(ec2, name="bastion", public=True)
            workloads = await drive_ec2_workloads(
                store, tenant_id=_TENANT, ec2_client=ec2, iam_client=iam
            )
        assert workloads and workloads[0].is_public, "the EC2 instance reads as internet-exposed"
        arn = workloads[0].instance_arn
        # Host scan: real trivy CVEs recorded onto the SAME instance-ARN node.
        await drive_vulnerability(store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=arn)

        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        hv = [p for p in paths if p.path_type == "internet_exposed_host_vulnerable"]
        assert len(hv) == 1
        assert hv[0].severity == 79
        assert hv[0].count >= 1  # at least one real CVE


@pytest.mark.asyncio
async def test_private_host_with_os_vuln_is_dark(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    async with in_memory_semantic_store() as store:
        with moto_full_clients(()) as (_s3, iam, _ecs, ec2, _sm):
            setup_ec2_instance(ec2, name="internal", public=False)
            workloads = await drive_ec2_workloads(
                store, tenant_id=_TENANT, ec2_client=ec2, iam_client=iam
            )
        assert workloads and not workloads[0].is_public
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=workloads[0].instance_arn
        )
        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        assert not [p for p in paths if p.path_type == "internet_exposed_host_vulnerable"]
