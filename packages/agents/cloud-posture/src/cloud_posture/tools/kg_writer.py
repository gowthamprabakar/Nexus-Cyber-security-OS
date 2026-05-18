"""Knowledge-graph writer (Postgres SemanticStore-backed).

Per the KG-loop-closure plan (2026-05-18) and the ADR-009 amendment of the
same date: Cloud Posture's KG write path targets the platform's Postgres
`SemanticStore` (the `entities` + `relationships` tables). The pre-existing
Neo4j-backed writer at `cloud_posture/tools/neo4j_kg.py` is preserved
DORMANT in the codebase — retained as the labelled door for the future
Phase-2 Neo4j swap (depth >= 4 + > 1M edges/tenant per ADR-009). This
file is the active writer.

Class shape is intentionally identical to the dormant `neo4j_kg`
`KnowledgeGraphWriter`: same class name, same method names, same parameter
names. The constructor's first argument is renamed from `driver` to
`semantic_store` (disclosed rename per ADR-010 condition 6). Callers
inside the agent reach this writer through the `kg_upsert_asset` and
`kg_upsert_finding` tool registrations whose action names are preserved
verbatim — F.6 audit-chain consumers see the same vocabulary.

`SemanticStore.add_relationship` is INSERT-only — repeated calls on the
same `(src_entity_id, dst_entity_id, relationship_type)` triple produce
duplicate rows. Cypher `MERGE` collapsed those at the database. Here, we
dedupe inside the writer: each instance keeps a per-finding `set[str]` of
asset external_ids it has already related to that finding, and skips the
`add_relationship` call when an arn is seen twice. Scope: this writer
instance only (a single agent run). The substrate (`charter.memory`) is
unmodified — we do not change `add_relationship` to upsert-by-tuple,
which would violate the plan's substrate-sealed watch-item.
"""

from __future__ import annotations

from typing import Any

from charter.memory import SemanticStore


class KnowledgeGraphWriter:
    """Customer-scoped writer for assets, findings, and AFFECTS edges.

    Mirrors the dormant `neo4j_kg.KnowledgeGraphWriter` class shape so the
    agent's tool registry re-points at this class with no caller change.
    Methods are `async` and side-effect-only; entity ids returned by the
    underlying `SemanticStore` calls are tracked internally to wire the
    AFFECTS relationship correctly, but are not exposed to callers.
    """

    def __init__(self, semantic_store: SemanticStore, customer_id: str) -> None:
        self._semantic_store = semantic_store
        self._customer_id = customer_id
        self._related_arns_per_finding: dict[str, set[str]] = {}

    async def upsert_asset(
        self,
        kind: str,
        external_id: str,
        properties: dict[str, Any],
    ) -> None:
        """Idempotent upsert of an asset entity.

        The dormant Cypher used `kind` as part of the MERGE key. Here, asset
        identity collapses to `(tenant_id, "asset", external_id)` — `kind`
        moves from key to property. This preserves the cross-Cloud-Posture-run
        invariant (one external_id == one asset entity) while staying within
        the substrate's three-column composite key.
        """
        merged: dict[str, Any] = {"kind": kind, **dict(properties)}
        await self._semantic_store.upsert_entity(
            tenant_id=self._customer_id,
            entity_type="asset",
            external_id=external_id,
            properties=merged,
        )

    async def upsert_finding(
        self,
        finding_id: str,
        rule_id: str,
        severity: str,
        affected_arns: list[str],
    ) -> None:
        """Idempotent upsert of a finding entity + AFFECTS edges per arn.

        For each affected arn: ensures the asset entity exists (idempotent
        on `(tenant_id, "asset", arn)`), then writes an AFFECTS edge from
        the finding to the asset — unless this writer instance has already
        related that arn to this finding, in which case the edge write is
        skipped. The dedup prevents duplicate AFFECTS rows that would
        otherwise accumulate when the agent revisits a finding within a
        scan (or when a fixture replays the same finding twice in tests).
        """
        finding_entity_id = await self._semantic_store.upsert_entity(
            tenant_id=self._customer_id,
            entity_type="finding",
            external_id=finding_id,
            properties={"rule_id": rule_id, "severity": severity},
        )
        if not affected_arns:
            return

        already_related = self._related_arns_per_finding.setdefault(finding_id, set())
        for arn in affected_arns:
            if arn in already_related:
                continue
            asset_entity_id = await self._semantic_store.upsert_entity(
                tenant_id=self._customer_id,
                entity_type="asset",
                external_id=arn,
                properties={},
            )
            await self._semantic_store.add_relationship(
                tenant_id=self._customer_id,
                src_entity_id=finding_entity_id,
                dst_entity_id=asset_entity_id,
                relationship_type="AFFECTS",
            )
            already_related.add(arn)
