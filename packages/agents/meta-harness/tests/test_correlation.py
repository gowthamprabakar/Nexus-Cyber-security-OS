"""Cross-agent correlation resolvers — the OWNED_BY + MATCHES_INDICATOR bridge edges (hermetic)."""

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.correlation import (
    correlate_all,
    link_deployed_via,
    link_ip_ownership,
    link_runtime_images,
    link_threat_indicators,
)
from meta_harness.kg_query import KgQuery

_R = NodeCategory.CLOUD_RESOURCE.value
_PE = NodeCategory.PROCESS_EVENT.value
_CVE = NodeCategory.CVE_FINDING.value
_IAC = NodeCategory.IAC_ARTIFACT.value


async def _node(store, t, etype, ext, props):
    return await store.upsert_entity(
        tenant_id=t, entity_type=etype, external_id=ext, properties=props
    )


async def _scene(store, t, *, dst_ip):
    """An instance owning 10.0.1.5, a flow 10.0.1.5→dst_ip, and a malicious-IP IOC."""
    inst = await _node(
        store,
        t,
        _R,
        "arn:aws:ec2:r:a:instance/i-1",
        {"kind": "ec2-instance", "is_public": True, "private_ips": ["10.0.1.5"]},
    )
    src = await _node(store, t, _R, "10.0.1.5", {"kind": "network-endpoint", "ip": "10.0.1.5"})
    dst = await _node(store, t, _R, dst_ip, {"kind": "network-endpoint", "ip": dst_ip})
    await store.add_relationship(
        tenant_id=t,
        src_entity_id=src,
        dst_entity_id=dst,
        relationship_type="COMMUNICATES_WITH",
        properties={},
    )
    await _node(store, t, "ioc", "ip:198.51.100.10", {"ioc_type": "ip", "value": "198.51.100.10"})
    return inst


@pytest.mark.asyncio
async def test_resolvers_write_bridge_edges_and_detector_fires():
    t = "t"
    async with in_memory_semantic_store() as store:
        await _scene(store, t, dst_ip="198.51.100.10")
        assert await link_ip_ownership(store, t) == 1  # OWNED_BY: src endpoint → instance
        assert await link_threat_indicators(store, t) == 1  # MATCHES_INDICATOR: dst endpoint → IOC

        hits = await KgQuery(store, t).find_resource_contacting_malicious_ip()
        assert len(hits) == 1
        assert hits[0].indicator_value == "198.51.100.10"


@pytest.mark.asyncio
async def test_no_ioc_match_means_no_indicator_edge_and_no_hit():
    t = "t"
    async with in_memory_semantic_store() as store:
        await _scene(store, t, dst_ip="93.184.216.34")  # destination is NOT the malicious IOC
        await correlate_all(store, t)
        assert await link_threat_indicators(store, t) == 0  # idempotent re-run, still no match
        assert await KgQuery(store, t).find_resource_contacting_malicious_ip() == []


@pytest.mark.asyncio
async def test_ip_ownership_requires_matching_private_ip():
    t = "t"
    async with in_memory_semantic_store() as store:
        await _node(
            store,
            t,
            _R,
            "arn:aws:ec2:r:a:instance/i-2",
            {"kind": "ec2-instance", "private_ips": ["10.0.9.9"]},  # different IP
        )
        await _node(store, t, _R, "10.0.1.5", {"kind": "network-endpoint", "ip": "10.0.1.5"})
        assert await link_ip_ownership(store, t) == 0  # no endpoint IP matches an instance IP


@pytest.mark.asyncio
async def test_runtime_image_bridge_and_detector_fires():
    t = "t"
    async with in_memory_semantic_store() as store:
        # A runtime event on a host carrying image_ref; vulnerability already scanned that image.
        event = await _node(store, t, _PE, "RUNTIME-PROCESS-X-001-e", {"finding_type": "process"})
        host = await _node(store, t, _R, "host-uid-1", {"image_ref": "myreg/app:1.0"})
        image = await _node(store, t, _R, "myreg/app:1.0", {"kind": "container-image"})
        cve = await _node(store, t, _CVE, "CVE-2020-7471", {"severity": "CRITICAL"})
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=event,
            dst_entity_id=host,
            relationship_type=EdgeType.EXECUTED_ON.value,
            properties={},
        )
        await store.add_relationship(
            tenant_id=t,
            src_entity_id=image,
            dst_entity_id=cve,
            relationship_type=EdgeType.VULNERABLE_TO.value,
            properties={},
        )
        assert await link_runtime_images(store, t) == 1  # RUNS_IMAGE: host → image

        hits = await KgQuery(store, t).find_runtime_exploit_on_vulnerable_workload()
        assert len(hits) == 1
        assert hits[0].cve_id == "CVE-2020-7471"


@pytest.mark.asyncio
async def test_runtime_image_bridge_skips_unknown_image():
    t = "t"
    async with in_memory_semantic_store() as store:
        # A runtime host whose image was never scanned → no image node to link to.
        await _node(store, t, _R, "host-uid-1", {"image_ref": "myreg/unscanned:1.0"})
        assert await link_runtime_images(store, t) == 0


@pytest.mark.asyncio
async def test_deployed_via_bridge_and_detector_fires():
    t = "t"
    async with in_memory_semantic_store() as store:
        # A resource tagged with IaC provenance + the matching IAC_ARTIFACT (a misconfigured file).
        await _node(
            store,
            t,
            _R,
            "arn:aws:ec2:r:a:instance/i-1",
            {"kind": "ec2-instance", "iac_artifact": "gh/acme/infra:main.tf"},
        )
        await _node(store, t, _IAC, "gh/acme/infra:main.tf", {"file": "main.tf"})
        assert await link_deployed_via(store, t) == 1  # DEPLOYED_VIA: resource → artifact

        hits = await KgQuery(store, t).find_resource_from_misconfigured_iac()
        assert len(hits) == 1
        assert hits[0].artifact_ref == "gh/acme/infra:main.tf"


@pytest.mark.asyncio
async def test_deployed_via_requires_matching_artifact():
    t = "t"
    async with in_memory_semantic_store() as store:
        # Resource provenance points to an artifact node that doesn't exist (no misconfig there).
        await _node(
            store,
            t,
            _R,
            "arn:aws:ec2:r:a:instance/i-2",
            {"kind": "ec2-instance", "iac_artifact": "gh/acme/infra:other.tf"},
        )
        await _node(store, t, _IAC, "gh/acme/infra:main.tf", {"file": "main.tf"})
        assert await link_deployed_via(store, t) == 0
