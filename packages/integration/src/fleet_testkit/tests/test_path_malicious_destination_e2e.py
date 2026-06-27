"""Cross-domain path A1 — owned resource communicating with a known-malicious IP, REAL e2e.

The first attack path spanning network-threat + threat-intel + cloud-posture. Drives all three
feeders' REAL writers into one store, runs the REAL correlation resolvers (the deferred 'Stage 3'
bridges), and asserts the malicious-destination detector fires:

- cloud-posture's REAL EC2 reader records a moto instance + its private IP.
- network-threat's REAL ``record_flows`` records a flow from that private IP to a destination IP.
- threat-intel's REAL ``upsert_ioc`` records the destination IP as a known-malicious IOC.
- ``correlate_all`` writes ``OWNED_BY`` (endpoint→instance) + ``MATCHES_INDICATOR`` (endpoint→IOC).
- ``AttackPathRanker`` surfaces "Communicating with malicious IP"; a flow to a benign IP stays dark.

Hermetic: the instance is moto-REAL; flows/IOCs are the agents' native parsed input types.
"""

import pytest
from meta_harness.attack_paths import AttackPathRanker
from meta_harness.correlation import correlate_all
from meta_harness.kg_query import KgQuery

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.moto_aws import drive_ec2_workloads, moto_all_clients, setup_ec2_instance
from fleet_testkit.network_intel import drive_network_flows, drive_threat_intel_iocs

_TENANT = "tenant-maldest"
_MALICIOUS_IP = "198.51.100.10"
_BENIGN_IP = "93.184.216.34"


async def _seed_instance(store) -> str:
    """Create a moto EC2 instance, record it via the real reader, return its private IP."""
    with moto_all_clients(()) as (_s3, iam, _ecs, ec2):
        private_ip = setup_ec2_instance(ec2, name="web")
        workloads = await drive_ec2_workloads(
            store, tenant_id=_TENANT, ec2_client=ec2, iam_client=iam
        )
    assert workloads and private_ip in workloads[0].private_ips, "instance recorded with its IP"
    return private_ip


@pytest.mark.asyncio
async def test_resource_beaconing_to_malicious_ip_lights_up() -> None:
    async with in_memory_semantic_store() as store:
        src_ip = await _seed_instance(store)
        await drive_network_flows(store, tenant_id=_TENANT, flows=((src_ip, _MALICIOUS_IP),))
        await drive_threat_intel_iocs(store, tenant_id=_TENANT, malicious_ips=(_MALICIOUS_IP,))

        await correlate_all(store, _TENANT)  # the deferred Stage-3 bridges, built

        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        mal = [p for p in paths if p.path_type == "malicious_destination"]
        assert len(mal) == 1, "the owned resource talking to a malicious IP surfaces one path"
        assert mal[0].evidence == (_MALICIOUS_IP,)
        assert mal[0].severity == 85


@pytest.mark.asyncio
async def test_resource_talking_to_benign_ip_is_dark() -> None:
    async with in_memory_semantic_store() as store:
        src_ip = await _seed_instance(store)
        # Same flow shape, but the destination is NOT in the IOC feed.
        await drive_network_flows(store, tenant_id=_TENANT, flows=((src_ip, _BENIGN_IP),))
        await drive_threat_intel_iocs(store, tenant_id=_TENANT, malicious_ips=(_MALICIOUS_IP,))

        await correlate_all(store, _TENANT)

        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        assert not [p for p in paths if p.path_type == "malicious_destination"]


@pytest.mark.asyncio
async def test_unowned_endpoint_talking_to_malicious_ip_is_dark() -> None:
    # A flow between two bare IPs with NO owning instance → no OWNED_BY → not our resource → dark.
    async with in_memory_semantic_store() as store:
        await drive_network_flows(store, tenant_id=_TENANT, flows=(("10.9.9.9", _MALICIOUS_IP),))
        await drive_threat_intel_iocs(store, tenant_id=_TENANT, malicious_ips=(_MALICIOUS_IP,))
        await correlate_all(store, _TENANT)
        paths = await AttackPathRanker(KgQuery(store, _TENANT)).find_all()
        assert not [p for p in paths if p.path_type == "malicious_destination"]
