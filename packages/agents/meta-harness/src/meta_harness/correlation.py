"""Cross-agent correlation resolvers — the deferred 'Stage 3' bridge edges, built.

The feeders write their own nodes keyed by their native identifiers (network keys endpoints by IP,
threat-intel keys IOCs by ``ip:<value>``, cloud-posture keys instances by ARN), which never
converge by key. These resolvers run AFTER the feeders populate the graph and BEFORE the detectors
query it, matching native keys to write the bridge edges that let cross-domain attack-path detectors
fire:

- :func:`link_ip_ownership` — a network endpoint's IP ∈ an EC2 instance's ``private_ips`` ⇒
  ``OWNED_BY`` (endpoint → instance). The IP→resource join ``network_threat.kg_writer`` defers.
- :func:`link_threat_indicators` — a network endpoint's IP == a threat-intel IOC's value ⇒
  ``MATCHES_INDICATOR`` (endpoint → IOC). The first edges threat-intel contributes to the graph.

Read-only over the feeders' nodes; the only writes are the bridge edges (idempotent — the
relationships UNIQUE index, ADR-022, makes a re-run a no-op).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from charter.memory.graph_types import EdgeType, NodeCategory

if TYPE_CHECKING:
    from charter.memory.semantic import SemanticStore


async def _cloud_resources(store: SemanticStore, tenant_id: str) -> list:
    return await store.list_entities_by_type(  # type: ignore[no-any-return]
        tenant_id=tenant_id, entity_type=NodeCategory.CLOUD_RESOURCE.value
    )


async def link_ip_ownership(store: SemanticStore, tenant_id: str) -> int:
    """Write ``OWNED_BY`` (network endpoint → EC2 instance) where the IP matches. Returns #edges."""
    resources = await _cloud_resources(store, tenant_id)
    ip_to_instance: dict[str, str] = {}
    for r in resources:
        if r.properties.get("kind") == "ec2-instance":
            for ip in r.properties.get("private_ips", []) or []:
                ip_to_instance[str(ip)] = r.entity_id

    count = 0
    for r in resources:
        if r.properties.get("kind") != "network-endpoint":
            continue
        instance_id = ip_to_instance.get(str(r.properties.get("ip", "")))
        if instance_id:
            await store.add_relationship(
                tenant_id=tenant_id,
                src_entity_id=r.entity_id,
                dst_entity_id=instance_id,
                relationship_type=EdgeType.OWNED_BY.value,
                properties={},
            )
            count += 1
    return count


async def link_threat_indicators(store: SemanticStore, tenant_id: str) -> int:
    """Write ``MATCHES_INDICATOR`` (network endpoint → IOC) where the IP matches. Returns #edges."""
    resources = await _cloud_resources(store, tenant_id)
    iocs = await store.list_entities_by_type(tenant_id=tenant_id, entity_type="ioc")
    ip_iocs: dict[str, str] = {
        str(i.properties.get("value", "")): i.entity_id
        for i in iocs
        if i.properties.get("ioc_type") == "ip"
    }

    count = 0
    for r in resources:
        if r.properties.get("kind") != "network-endpoint":
            continue
        ioc_id = ip_iocs.get(str(r.properties.get("ip", "")))
        if ioc_id:
            await store.add_relationship(
                tenant_id=tenant_id,
                src_entity_id=r.entity_id,
                dst_entity_id=ioc_id,
                relationship_type=EdgeType.MATCHES_INDICATOR.value,
                properties={},
            )
            count += 1
    return count


async def correlate_all(store: SemanticStore, tenant_id: str) -> None:
    """Run every cross-agent bridge resolver for a tenant (call after feeders, before detectors)."""
    await link_ip_ownership(store, tenant_id)
    await link_threat_indicators(store, tenant_id)


__all__ = ["correlate_all", "link_ip_ownership", "link_threat_indicators"]
