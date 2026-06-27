"""B2 — the scan loop end to end: populated graph -> analyze() -> ranked answer, timed.

Proves the loop CORRELATES, not just ranks: an EC2 instance + a flow to a known-malicious IP only
surfaces the malicious_destination path if ``analyze`` runs the cross-agent bridge resolvers first
(the bug the old CLI had — it called find_all() without correlate_all). Also times the analysis
step: on a populated graph it is sub-second; real-cloud "within minutes" latency is dominated by
the feeders' live API calls (operator-measured), not this orchestration.
"""

import time

import pytest
from meta_harness.scan import analyze

from fleet_testkit import in_memory_semantic_store
from fleet_testkit.moto_aws import drive_ec2_workloads, moto_all_clients, setup_ec2_instance
from fleet_testkit.network_intel import drive_network_flows, drive_threat_intel_iocs

_TENANT = "tenant-loop"
_MALICIOUS_IP = "198.51.100.10"


@pytest.mark.asyncio
async def test_scan_loop_correlates_then_ranks_quickly() -> None:
    async with in_memory_semantic_store() as store:
        # Feeders populate the graph (cross-domain: cloud-posture + network + threat-intel).
        with moto_all_clients(()) as (_s3, iam, _ecs, ec2):
            ip = setup_ec2_instance(ec2, name="web")
            await drive_ec2_workloads(store, tenant_id=_TENANT, ec2_client=ec2, iam_client=iam)
        await drive_network_flows(store, tenant_id=_TENANT, flows=((ip, _MALICIOUS_IP),))
        await drive_threat_intel_iocs(store, tenant_id=_TENANT, malicious_ips=(_MALICIOUS_IP,))

        # The loop: correlate_all + rank + candidates, in one call, timed.
        started = time.monotonic()
        result = await analyze(store, _TENANT)
        elapsed = time.monotonic() - started

        # Correlation ran inside analyze — else this cross-domain path would not fire.
        assert "malicious_destination" in {p.path_type for p in result.confirmed}
        # Orchestration overhead is negligible; "within minutes" is the feeders' live cost, not this.
        assert elapsed < 5.0, f"analyze took {elapsed:.2f}s — orchestration should be sub-second"


@pytest.mark.asyncio
async def test_scan_loop_empty_graph_is_clean() -> None:
    async with in_memory_semantic_store() as store:
        result = await analyze(store, _TENANT)
        assert result.confirmed == [] and result.candidates == []
