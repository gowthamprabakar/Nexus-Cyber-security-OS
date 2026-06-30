"""Network-threat knowledge-graph writer (v0.4 Stage 1.4/D.4).

Writes the **observed network topology** the catalogue (#711) assigns C.x Network into
the fleet graph from the typed ``FlowRecord``s the agent already ingests: each flow's
two endpoints + a ``COMMUNICATES_WITH`` edge (the catalogue's "observed from flow logs"
edge). Computed **reachability** (``CAN_REACH`` / ``EXPOSED_TO``, derived over D.3/D.5
security-group + route-table config) stays **Stage 3 correlation** (decision #715a) —
this writer only records what was actually observed.

Endpoints are keyed by IP as ``CLOUD_RESOURCE`` placeholders (``kind=network-endpoint``);
resolving an IP to its owning cloud resource is Stage 3 correlation, not this writer.

Subclasses :class:`KnowledgeGraphWriterBase` (ADR-019): tenant scoping, typed
vocabulary (ADR-018), within-run dedup, opt-in/inert when no store. Offline default
writes nothing → findings.json byte-identical.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from network_threat.schemas import FlowRecord


class KnowledgeGraphWriter(KnowledgeGraphWriterBase):
    """Persists observed network endpoints + COMMUNICATES_WITH edges from flows."""

    async def record_flows(self, flow_records: Iterable[FlowRecord]) -> None:
        """Upsert each flow's src/dst endpoint + a COMMUNICATES_WITH edge (deduped)."""
        for flow in flow_records:
            if not flow.src_ip or not flow.dst_ip:
                continue
            src = await self.upsert_node(
                NodeCategory.CLOUD_RESOURCE,
                flow.src_ip,
                {"ip": flow.src_ip, "kind": "network-endpoint"},
            )
            dst = await self.upsert_node(
                NodeCategory.CLOUD_RESOURCE,
                flow.dst_ip,
                {"ip": flow.dst_ip, "kind": "network-endpoint"},
            )
            await self.add_edge(
                src or "",
                dst or "",
                EdgeType.COMMUNICATES_WITH,
                {"dst_port": flow.dst_port, "protocol": flow.protocol},
            )

    async def record_reachability(self, grants: Sequence[tuple[str, str, str, str]]) -> None:
        """Write CLOUD_RESOURCE --CAN_REACH--> CLOUD_RESOURCE edges (derived reachability, slice #2).

        Each grant is ``(src_resource_id, dst_resource_id, method, via)``: ``src`` can reach ``dst``
        over the network per security-group config (``method=lateral_sg``). Unlike ``record_flows``
        (observed traffic), this is *derived* — the Stage 3 reachability decision #715a parked. Both
        endpoints upserted onto the shared CLOUD_RESOURCE spine; the path engine traverses CAN_REACH
        so lateral-movement paths (public foothold → reachable private/vulnerable host) emerge.
        """
        for src_id, dst_id, method, via in grants:
            src = await self.upsert_node(NodeCategory.CLOUD_RESOURCE, src_id, {})
            dst = await self.upsert_node(NodeCategory.CLOUD_RESOURCE, dst_id, {})
            await self.add_edge(
                src or "", dst or "", EdgeType.CAN_REACH, {"method": method, "via": via}
            )


__all__ = ["KnowledgeGraphWriter"]
