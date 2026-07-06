"""Path lateral_reachable: find_lateral_movement_via_reachability — a public foothold that
CAN_REACH / PEERED_WITH a target which is a vulnerable host or a managed datastore.
Distinct from find_lateral_movement_to_vulnerable_host (observed COMMUNICATES_WITH);
this fires from config alone (derived reachability). Read-only.

Test matrix:
  1. CAN_REACH → vuln-host (VULNERABLE_TO CVE): impact="vulnerable_host"
  2. CAN_REACH → rds-instance (kind): impact="sensitive_resource"
  3. PEERED_WITH → vuln-host: reach_kind="vpc_peering"
  4. Private foothold (is_public=False): no hit
  5. No reach edge: no hit
"""

from __future__ import annotations

import pytest
from charter.memory.graph_types import EdgeType, NodeCategory
from fleet_testkit import in_memory_semantic_store
from meta_harness.kg_query import KgQuery, LateralReachable

_TENANT = "t-lateral-reachable"


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


async def _seed_foothold(store, *, tenant: str, is_public: bool) -> str:
    """Write a CLOUD_RESOURCE foothold node; return its entity_id."""
    return await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id="arn:aws:ec2:us-east-1:111:instance/i-foothold",
        properties={"kind": "ec2-instance", "is_public": is_public},
    )


async def _seed_vuln_host(store, *, tenant: str, cve_id: str = "CVE-2021-44228") -> tuple[str, str]:
    """Write a CLOUD_RESOURCE target with VULNERABLE_TO a CVE; return (target_id, cve_entity_id)."""
    target = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id="arn:aws:ec2:us-east-1:111:instance/i-target-host",
        properties={"kind": "ec2-instance", "is_public": False},
    )
    cve = await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CVE_FINDING.value,
        external_id=cve_id,
        properties={"severity": "CRITICAL"},
    )
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=target,
        dst_entity_id=cve,
        relationship_type=EdgeType.VULNERABLE_TO.value,
        properties={},
    )
    return target, cve


async def _seed_rds_target(store, *, tenant: str) -> str:
    """Write a CLOUD_RESOURCE rds-instance target; return its entity_id."""
    return await store.upsert_entity(
        tenant_id=tenant,
        entity_type=NodeCategory.CLOUD_RESOURCE.value,
        external_id="arn:aws:rds:us-east-1:111:db:internal-db",
        properties={"kind": "rds-instance", "is_public": False, "engine": "mysql"},
    )


async def _add_can_reach(
    store, *, tenant: str, src: str, dst: str, method: str = "lateral_sg"
) -> None:
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=src,
        dst_entity_id=dst,
        relationship_type=EdgeType.CAN_REACH.value,
        properties={"method": method, "via": "tcp:443"},
    )


async def _add_peered_with(store, *, tenant: str, src: str, dst: str) -> None:
    await store.add_relationship(
        tenant_id=tenant,
        src_entity_id=src,
        dst_entity_id=dst,
        relationship_type=EdgeType.PEERED_WITH.value,
        properties={"method": "vpc_peering", "via": "vpc-a<->vpc-b"},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_can_reach_to_vuln_host_emits_vulnerable_host_hit() -> None:
    """CAN_REACH from public foothold to a host with VULNERABLE_TO → impact=vulnerable_host."""
    async with in_memory_semantic_store() as store:
        foothold = await _seed_foothold(store, tenant=_TENANT, is_public=True)
        target, _cve = await _seed_vuln_host(store, tenant=_TENANT)
        await _add_can_reach(store, tenant=_TENANT, src=foothold, dst=target)

        hits = await KgQuery(store, _TENANT).find_lateral_movement_via_reachability()

        assert len(hits) == 1
        h = hits[0]
        assert isinstance(h, LateralReachable)
        assert h.foothold_id == foothold
        assert h.target_id == target
        assert h.reach_kind == "lateral_sg"
        assert h.impact == "vulnerable_host"
        assert h.cve_id == "CVE-2021-44228"
        assert h.severity == "CRITICAL"


@pytest.mark.asyncio
async def test_can_reach_to_rds_emits_sensitive_resource_hit() -> None:
    """CAN_REACH from public foothold to an rds-instance → impact=sensitive_resource."""
    async with in_memory_semantic_store() as store:
        foothold = await _seed_foothold(store, tenant=_TENANT, is_public=True)
        rds = await _seed_rds_target(store, tenant=_TENANT)
        await _add_can_reach(store, tenant=_TENANT, src=foothold, dst=rds)

        hits = await KgQuery(store, _TENANT).find_lateral_movement_via_reachability()

        assert len(hits) == 1
        h = hits[0]
        assert h.foothold_id == foothold
        assert h.target_id == rds
        assert h.reach_kind == "lateral_sg"
        assert h.impact == "sensitive_resource"
        assert h.cve_id == ""


@pytest.mark.asyncio
async def test_peered_with_to_vuln_host_uses_vpc_peering_reach_kind() -> None:
    """PEERED_WITH from public foothold to a vuln-host → reach_kind=vpc_peering."""
    async with in_memory_semantic_store() as store:
        foothold = await _seed_foothold(store, tenant=_TENANT, is_public=True)
        target, _cve = await _seed_vuln_host(store, tenant=_TENANT)
        await _add_peered_with(store, tenant=_TENANT, src=foothold, dst=target)

        hits = await KgQuery(store, _TENANT).find_lateral_movement_via_reachability()

        assert len(hits) == 1
        h = hits[0]
        assert h.reach_kind == "vpc_peering"
        assert h.impact == "vulnerable_host"
        assert h.cve_id == "CVE-2021-44228"


@pytest.mark.asyncio
async def test_private_foothold_is_dark() -> None:
    """A non-public foothold with CAN_REACH must not emit any hit."""
    async with in_memory_semantic_store() as store:
        foothold = await _seed_foothold(store, tenant=_TENANT, is_public=False)
        target, _cve = await _seed_vuln_host(store, tenant=_TENANT)
        await _add_can_reach(store, tenant=_TENANT, src=foothold, dst=target)

        hits = await KgQuery(store, _TENANT).find_lateral_movement_via_reachability()
        assert hits == []


@pytest.mark.asyncio
async def test_no_reach_edge_is_dark() -> None:
    """A public foothold with no CAN_REACH / PEERED_WITH edges must not emit any hit."""
    async with in_memory_semantic_store() as store:
        await _seed_foothold(store, tenant=_TENANT, is_public=True)
        await _seed_vuln_host(store, tenant=_TENANT)

        hits = await KgQuery(store, _TENANT).find_lateral_movement_via_reachability()
        assert hits == []
