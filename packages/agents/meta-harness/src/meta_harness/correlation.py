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


async def link_runtime_images(store: SemanticStore, tenant_id: str) -> int:
    """Write ``RUNS_IMAGE`` (runtime host → image node) where the host's image_ref matches an image
    vulnerability already scanned. Returns #edges.

    Runtime findings carry the workload's ``image_ref`` on the host node; it is the SAME key
    vulnerability writes its CVE ``VULNERABLE_TO`` edges onto. Linking the runtime host to that
    image node connects an active runtime detection to the image's known CVEs (cross-domain path
    A2) — the same image-ref bridge proven for paths 2/6, no host-id→instance resolution needed.
    Only links to an image node that already exists (vulnerability scanned it); otherwise there is
    no CVE to reach and the edge is pointless.
    """
    resources = await _cloud_resources(store, tenant_id)
    by_external_id = {r.external_id: r.entity_id for r in resources}
    k8s_hosts = await store.list_entities_by_type(
        tenant_id=tenant_id, entity_type=NodeCategory.K8S_OBJECT.value
    )
    hosts = [r for r in (*resources, *k8s_hosts) if r.properties.get("image_ref")]

    count = 0
    for host in hosts:
        image_id = by_external_id.get(str(host.properties.get("image_ref", "")))
        if image_id and image_id != host.entity_id:
            await store.add_relationship(
                tenant_id=tenant_id,
                src_entity_id=host.entity_id,
                dst_entity_id=image_id,
                relationship_type=EdgeType.RUNS_IMAGE.value,
                properties={},
            )
            count += 1
    return count


async def link_deployed_via(store: SemanticStore, tenant_id: str) -> int:
    """Write ``DEPLOYED_VIA`` (cloud resource → IaC artifact) where provenance matches. Returns #edges.

    The code-to-cloud bridge, run from the cloud side (the honest direction — appsec knows the code,
    not the deployed target). A cloud resource carries its IaC provenance as an ``iac_artifact``
    property (the ``IAC_ARTIFACT`` external_id ``{repo_slug}:{file}``, read from a ``nexus:iac``
    resource tag); appsec writes the ``IAC_ARTIFACT`` node only when that file has a misconfiguration.
    Matching them links a live resource to the misconfigured IaC it was deployed from.
    """
    resources = await _cloud_resources(store, tenant_id)
    artifacts = await store.list_entities_by_type(
        tenant_id=tenant_id, entity_type=NodeCategory.IAC_ARTIFACT.value
    )
    artifact_ids = {a.external_id: a.entity_id for a in artifacts}

    count = 0
    for r in resources:
        artifact_id = artifact_ids.get(str(r.properties.get("iac_artifact", "")))
        if artifact_id:
            await store.add_relationship(
                tenant_id=tenant_id,
                src_entity_id=r.entity_id,
                dst_entity_id=artifact_id,
                relationship_type=EdgeType.DEPLOYED_VIA.value,
                properties={},
            )
            count += 1
    return count


async def correlate_all(store: SemanticStore, tenant_id: str) -> None:
    """Run every cross-agent bridge resolver for a tenant (call after feeders, before detectors)."""
    await link_ip_ownership(store, tenant_id)
    await link_threat_indicators(store, tenant_id)
    await link_runtime_images(store, tenant_id)
    await link_deployed_via(store, tenant_id)


__all__ = [
    "correlate_all",
    "link_deployed_via",
    "link_ip_ownership",
    "link_runtime_images",
    "link_threat_indicators",
]
