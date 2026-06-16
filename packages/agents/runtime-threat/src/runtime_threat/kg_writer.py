"""Runtime-threat knowledge-graph writer (v0.4 Stage 1.1).

Writes the **runtime inventory** the catalogue (#711) assigns to C.x Runtime into
the fleet graph: the workload **host** node each finding describes + the **L6
behaviour event** that triggered it, linked by ``EXECUTED_ON`` (event → host).

Scope (Option X = inventory discovery): inventory only. The detection *finding*
node and its decoration of the host (findings-as-decorations) is the Stage 3
migration's job (#718-D4 / directive §5), not this writer — so this writer stays
within the existing ADR-018 type catalogue (no finding-node category needed).

Subclasses the shared :class:`KnowledgeGraphWriterBase` (ADR-019): tenant scoping,
typed vocabulary, within-run dedup, and opt-in/inert when no store is injected all
come from the base. Offline default (no ``SemanticStore``) writes nothing →
``findings.json`` is byte-identical.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase

from runtime_threat.schemas import FindingType, RuntimeFinding

if TYPE_CHECKING:
    from collections.abc import Iterable

#: FindingType → the L6 event node category it manifests as (catalogue C.x Runtime).
#: FILE integrity changes are file-integrity events; everything else is process
#: behaviour (process/syscall/osquery/network are all process-driven on the host).
_EVENT_CATEGORY: dict[FindingType, NodeCategory] = {
    FindingType.PROCESS: NodeCategory.PROCESS_EVENT,
    FindingType.SYSCALL: NodeCategory.PROCESS_EVENT,
    FindingType.OSQUERY: NodeCategory.PROCESS_EVENT,
    FindingType.NETWORK: NodeCategory.PROCESS_EVENT,
    FindingType.FILE: NodeCategory.FILE_INTEGRITY_EVENT,
}


class KnowledgeGraphWriter(KnowledgeGraphWriterBase):
    """Persists runtime hosts + L6 behaviour events for the fleet inventory graph."""

    async def record_finding(self, finding: RuntimeFinding) -> None:
        """Upsert the finding's L6 event node + each affected host, linked EXECUTED_ON."""
        event_category = _EVENT_CATEGORY.get(finding.finding_type, NodeCategory.PROCESS_EVENT)
        event_id = await self.upsert_node(
            event_category,
            finding.finding_id,
            {
                "finding_type": finding.finding_type.value,
                "severity": finding.severity.value,
                "title": finding.title,
            },
        )
        for host in finding.affected_hosts:
            host_id = str(host.get("uid", ""))
            if not host_id:
                continue
            namespace = str(host.get("namespace", ""))
            # A namespaced host is a Kubernetes workload (D.6 owns the node; runtime
            # contributes the L6 behaviour); otherwise it is a VM/host cloud resource.
            category = NodeCategory.K8S_OBJECT if namespace else NodeCategory.CLOUD_RESOURCE
            image = host.get("image")
            image_ref = str(image.get("ref", "")) if isinstance(image, dict) else ""
            host_node = await self.upsert_node(
                category,
                host_id,
                {
                    "hostname": str(host.get("hostname", "")),
                    "image_ref": image_ref,
                    "namespace": namespace,
                },
            )
            await self.add_edge(event_id or "", host_node or "", EdgeType.EXECUTED_ON)

    async def record_findings(self, findings: Iterable[RuntimeFinding]) -> None:
        for finding in findings:
            await self.record_finding(finding)


__all__ = ["KnowledgeGraphWriter"]
