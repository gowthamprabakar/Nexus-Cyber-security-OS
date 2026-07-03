"""v0.5 Item 2 — smallest synthetic dense-tenant generator to stress the walker.

Plants `breadth` source->sink chains of `depth` hops (public source -> ASSUMES* -> HAS_ACCESS_TO
resource -> EXPOSES_DATA data-sink) plus `noise` dead-end ASSUMES edges that lengthen the frontier
without reaching a sink. Returns the planted sink ids for recall scoring. NOT a general graph
fuzzer — just enough to measure the depth/cost/noise trade-off (ponytail).
"""

from __future__ import annotations

from typing import Any

from charter.memory.graph_types import EdgeType, NodeCategory


async def plant_dense_tenant(
    store: Any, tenant: str, *, breadth: int, depth: int, noise: int
) -> dict[str, Any]:
    async def node(ext: str, etype: str, props: dict[str, Any]) -> str:
        result: str = await store.upsert_entity(
            tenant_id=tenant, entity_type=etype, external_id=ext, properties=props
        )
        return result

    async def edge(src: str, dst: str, rel: str) -> None:
        await store.add_relationship(
            tenant_id=tenant,
            src_entity_id=src,
            dst_entity_id=dst,
            relationship_type=rel,
            properties={},
        )

    planted: list[str] = []
    for b in range(breadth):
        src = await node(f"arn:src:{b}", NodeCategory.CLOUD_RESOURCE.value, {"is_public": True})
        prev = src
        for h in range(max(0, depth - 2)):  # intermediate ASSUMES hops (non-source nodes)
            nxt = await node(f"hop:{b}:{h}", NodeCategory.CLOUD_RESOURCE.value, {})
            await edge(prev, nxt, EdgeType.ASSUMES.value)
            prev = nxt
        res = await node(f"arn:res:{b}", NodeCategory.CLOUD_RESOURCE.value, {})
        await edge(prev, res, EdgeType.HAS_ACCESS_TO.value)
        data = await node(f"data:{b}", NodeCategory.DATA_CLASSIFICATION.value, {"data_type": "ssn"})
        await edge(res, data, EdgeType.EXPOSES_DATA.value)
        planted.append(data)

    for n in range(noise):
        a = await node(f"noise:{n}:a", NodeCategory.IDENTITY.value, {})
        c = await node(f"noise:{n}:b", NodeCategory.IDENTITY.value, {})
        await edge(a, c, EdgeType.ASSUMES.value)

    return {"planted_sinks": planted, "breadth": breadth, "depth": depth, "noise": noise}


__all__ = ["plant_dense_tenant"]
