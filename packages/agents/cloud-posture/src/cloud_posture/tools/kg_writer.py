"""Knowledge-graph writer (Postgres SemanticStore-backed).

Per the KG-loop-closure plan (2026-05-18) and the ADR-009 amendment of the
same date: Cloud Posture's KG write path targets the platform's Postgres
``SemanticStore``. The pre-existing Neo4j-backed writer at
``cloud_posture/tools/neo4j_kg.py`` is preserved DORMANT — the labelled door for
the future Phase-2 Neo4j swap (depth >= 4 + > 1M edges/tenant per ADR-009). This
file is the active writer.

v0.4 Stage 1 (operator decision #718-D1 / ADR-019): this writer is reparented
onto :class:`charter.memory.kg_writer_base.KnowledgeGraphWriterBase` — the shared
base every agent's ``kg_writer`` now subclasses (tenant scoping, within-run edge
dedup, opt-in/inert). The node/edge vocabulary moves to the **ADR-018 catalogue**
so Cloud Posture's resources are the SAME ``CLOUD_RESOURCE`` spine nodes that the
D.1/D.2/D.4/D.5 writers' edges resolve against (operator decision: coherent spine):

- ``asset`` → :attr:`NodeCategory.CLOUD_RESOURCE` (``kind`` stays a property).
- ``finding`` → :attr:`NodeCategory.MISCONFIGURATION_FINDING`.
- ``AFFECTS`` → :attr:`EdgeType.AFFECTS`.

Public method signatures (``upsert_asset`` / ``upsert_finding``) and the agent's
tool action names (``kg_upsert_asset`` / ``kg_upsert_finding``) are unchanged, so
F.6 audit-chain consumers see the same vocabulary and ``findings.json`` stays
byte-identical (the eval back-compat gate). Behaviour is unchanged: the base's
``(src, dst, edge)`` dedup is exactly the old per-finding ``(finding_id, arn)``
dedup — same finding_id ⇒ same finding entity_id, same arn ⇒ same asset entity_id,
so repeats collapse and cross-finding edges to a shared asset both land.

The substrate (``charter.memory``) is unmodified — ``add_relationship`` stays
INSERT-only; cross-RUN duplicate-edge dedup is the separate Stage 3 PR (#718-D3).
"""

from __future__ import annotations

from typing import Any

from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.kg_writer_base import KnowledgeGraphWriterBase


class KnowledgeGraphWriter(KnowledgeGraphWriterBase):
    """Customer-scoped writer for resources, misconfigurations, and AFFECTS edges.

    Subclasses :class:`KnowledgeGraphWriterBase` (ADR-019); the constructor
    (``semantic_store``, ``customer_id``) is inherited. Methods are ``async`` and
    side-effect-only.
    """

    async def upsert_asset(
        self,
        kind: str,
        external_id: str,
        properties: dict[str, Any],
    ) -> None:
        """Idempotent upsert of a cloud-resource (spine) node.

        Asset identity collapses to ``(tenant_id, "cloud_resource", external_id)``;
        ``kind`` moves from the dormant-Cypher MERGE key to a property. This is the
        spine node the cross-agent edges (VULNERABLE_TO, HAS_ACCESS_TO, …) point at.
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

        For each affected arn: ensures the ``CLOUD_RESOURCE`` spine node exists
        (idempotent), then writes an ``AFFECTS`` edge from the finding to the
        resource. The base's within-run ``(src, dst, edge)`` dedup skips a repeat
        of the same ``(finding, resource)`` pair — preserving the old per-finding
        dedup semantics that compensate for ``add_relationship`` being INSERT-only.
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
