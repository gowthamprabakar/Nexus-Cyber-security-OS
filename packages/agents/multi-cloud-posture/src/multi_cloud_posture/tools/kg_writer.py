"""Knowledge-graph writer (Postgres SemanticStore-backed) — D.15 Multi-Cloud Posture.

Stage 1.7 (operator R-2 resolution): D.15 previously had **no** graph-writer, so its
Azure/GCP findings never reached the shared `SemanticStore` spine — a gap the fleet-test
directive surfaced (T2 scenario 9 + T5 route D.5/Azure findings through the graph). This adds
the writer, mirroring the cloud-posture (F.3) #733 refactor exactly:

- ``asset`` → :attr:`NodeCategory.CLOUD_RESOURCE` (``kind`` = Azure/GCP resource type, a property).
- ``finding`` → :attr:`NodeCategory.MISCONFIGURATION_FINDING`.
- ``AFFECTS`` → :attr:`EdgeType.AFFECTS`.

D.15 reuses cloud-posture's ``CloudPostureFinding`` (re-exported from F.3), so the resources +
finding shape — and therefore this writer — are identical to cloud-posture's. The Azure/GCP
resources become the SAME ``CLOUD_RESOURCE`` spine nodes the D.1/D.2/D.4 writers' edges resolve
against (coherent spine).

**Scope (operator R-2):** this writes inventory from **fixture-mode** (offline feed) findings —
it does NOT touch the live-connector deferral (Azure/GCP live readers stay v0.5). The "D.15
fixture-mode" decision survives intact. The substrate (``charter.memory``) is unmodified; this
subclasses the shared :class:`KnowledgeGraphWriterBase` (ADR-019) — opt-in / inert when no store.
"""

from __future__ import annotations

from typing import Any

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase


class KnowledgeGraphWriter(KnowledgeGraphWriterBase):
    """Customer-scoped writer for cloud resources, misconfigurations, and AFFECTS edges.

    Subclasses :class:`KnowledgeGraphWriterBase` (ADR-019); the constructor
    (``semantic_store``, ``customer_id``) is inherited. Methods are ``async`` and
    side-effect-only. Byte-identical in shape to the cloud-posture writer so cross-cloud
    resources share one spine.
    """

    async def upsert_asset(
        self,
        kind: str,
        external_id: str,
        properties: dict[str, Any],
    ) -> None:
        """Idempotent upsert of a cloud-resource (spine) node.

        Identity collapses to ``(tenant_id, "cloud_resource", external_id)``; ``kind`` (the
        Azure/GCP resource type) moves to a property. This is the spine node the cross-agent
        edges point at.
        """
        await self.upsert_node(
            NodeCategory.CLOUD_RESOURCE,
            external_id,
            {"kind": kind, **dict(properties)},
        )

    async def upsert_finding(
        self,
        finding_id: str,
        rule_id: str,
        severity: str,
        affected_arns: list[str],
    ) -> None:
        """Idempotent upsert of a misconfiguration-finding node + AFFECTS edges.

        For each affected resource id: ensures the ``CLOUD_RESOURCE`` spine node exists
        (idempotent), then writes an ``AFFECTS`` edge from the finding to the resource. The
        base's within-run ``(src, dst, edge)`` dedup collapses a repeat of the same
        ``(finding, resource)`` pair; cross-run dedup is the DB UNIQUE index (ADR-022).
        """
        finding_node = await self.upsert_node(
            NodeCategory.MISCONFIGURATION_FINDING,
            finding_id,
            {"rule_id": rule_id, "severity": severity},
        )
        for arn in affected_arns:
            asset_node = await self.upsert_node(NodeCategory.CLOUD_RESOURCE, arn, {})
            await self.add_edge(finding_node or "", asset_node or "", EdgeType.AFFECTS)


__all__ = ["KnowledgeGraphWriter"]
