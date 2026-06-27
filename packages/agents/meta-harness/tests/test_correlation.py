"""Cross-agent correlation resolvers — the OWNED_BY + MATCHES_INDICATOR bridge edges (hermetic)."""

import pytest
from charter.memory.graph_types import NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.correlation import (
    correlate_all,
    link_ip_ownership,
    link_threat_indicators,
)
from meta_harness.kg_query import KgQuery

_R = NodeCategory.CLOUD_RESOURCE.value


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
