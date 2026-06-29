"""Path #14 — network lateral movement, REAL e2e.

Ties four real feeders into one lateral-movement path through their own code + the IP-ownership
correlation bridge:

- two EC2 instances (a public foothold + an internal target) via cloud-posture's real reader.
- an observed VPC flow foothold->target via network-threat's real ``record_flows``.
- a real ``trivy`` host scan recording a CVE onto the internal target's instance node.
- ``correlate_all`` writes the network-endpoint -> instance ``OWNED_BY`` bridge edges.
- ``KgQuery.find_lateral_movement_to_vulnerable_host`` lights up the foothold->target pivot.

The EC2/flow legs are hermetic (moto); the vuln leg is trivy-gated (real binary). No hand-faked
findings — the CVE is detected by real Trivy.
"""

import pytest
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.correlation import correlate_all
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.moto_aws import drive_ec2_workloads, moto_full_clients, setup_ec2_instance
from fleet_testkit.network_intel import drive_network_flows
from fleet_testkit.vuln_scan import drive_vulnerability, trivy_available

pytestmark = pytest.mark.skipif(not trivy_available, reason="trivy binary not installed")

_TENANT = "tenant-lateral"


def _write_vulnerable_fixture(root) -> None:
    (root / "requirements.txt").write_text("Django==2.0.0\n")


@pytest.mark.asyncio
async def test_public_foothold_to_vulnerable_internal_host_lights_up(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    async with in_memory_semantic_store() as store:
        with moto_full_clients(()) as (_s3, iam, _ecs, ec2, _sm):
            foothold_ip = setup_ec2_instance(ec2, name="bastion", public=True)
            target_ip = setup_ec2_instance(
                ec2, name="internal", public=False, subnet_cidr="10.0.2.0/24"
            )
            workloads = await drive_ec2_workloads(
                store, tenant_id=_TENANT, ec2_client=ec2, iam_client=iam
            )
        target = next(w for w in workloads if not w.is_public)
        # Observed flow foothold -> internal target.
        await drive_network_flows(store, tenant_id=_TENANT, flows=((foothold_ip, target_ip),))
        # The internal target carries a real host CVE (keyed by its instance ARN).
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=target.instance_arn
        )
        # Bridge: network-endpoint -> instance OWNED_BY edges.
        await correlate_all(store, _TENANT)

        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        lm = [p for p in paths if p.path_type == "lateral_movement"]
        assert len(lm) == 1
        assert lm[0].severity == 82
        assert lm[0].count >= 1  # at least one real target CVE


@pytest.mark.asyncio
async def test_no_flow_to_target_is_dark(tmp_path) -> None:
    _write_vulnerable_fixture(tmp_path)
    async with in_memory_semantic_store() as store:
        with moto_full_clients(()) as (_s3, iam, _ecs, ec2, _sm):
            setup_ec2_instance(ec2, name="bastion", public=True)
            target_ip = setup_ec2_instance(
                ec2, name="internal", public=False, subnet_cidr="10.0.2.0/24"
            )
            workloads = await drive_ec2_workloads(
                store, tenant_id=_TENANT, ec2_client=ec2, iam_client=iam
            )
        target = next(w for w in workloads if not w.is_public)
        # Target is vulnerable, but NO flow reaches it from the foothold.
        await drive_network_flows(store, tenant_id=_TENANT, flows=(("9.9.9.9", target_ip),))
        await drive_vulnerability(
            store, tenant_id=_TENANT, fixture_dir=tmp_path, image_ref=target.instance_arn
        )
        await correlate_all(store, _TENANT)
        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        assert not [p for p in paths if p.path_type == "lateral_movement"]
