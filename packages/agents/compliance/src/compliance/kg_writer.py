"""Knowledge-graph writer for the D.9 Compliance agent (Postgres SemanticStore-backed).

Per Q3 / Q5 of the D.9 v0.1 plan, compliance entities (framework / control)
are persisted to the platform's Postgres ``SemanticStore`` using the same
pattern proven in F.3 v0.1.5 (KG-loop closure) and re-used in D.5 / D.8.

**Single-tenant ``semantic_store=None`` opt-in default.** Per the Path-B
operating rule §11.1: multi-tenant production blocks on the future
SET LOCAL ``$1`` tenant-RLS substrate-fix plan. v0.1 keeps the agent
driver path that constructs the writer guarded — when ``semantic_store``
is None at the agent boundary, the writer is never instantiated and no
SemanticStore writes happen.

The writer is **side-effect-only** (returns ``None``); upserts are
idempotent per the substrate's composite key
``(tenant_id, entity_type, external_id)``.

Q6 reminder: this writer persists framework metadata + paraphrased
control descriptions only. No PII; no verbatim CIS Benchmark text.
"""

from __future__ import annotations

from charter.memory import SemanticStore

from compliance.entities import ControlEntity, FrameworkEntity


class KnowledgeGraphWriter:
    """Customer-scoped writer for framework + control entities.

    Mirrors F.3 / D.5 / D.8's ``KnowledgeGraphWriter`` shape: ``async``
    methods, side-effect-only. The substrate's composite key for
    entities is ``(tenant_id, entity_type, external_id)``; the
    writer's ``upsert_*`` methods produce the external_id from the
    entity's identifying fields (framework value, or
    framework:control_id pair).
    """

    def __init__(self, semantic_store: SemanticStore, customer_id: str) -> None:
        self._semantic_store = semantic_store
        self._customer_id = customer_id

    async def upsert_framework(self, framework: FrameworkEntity) -> None:
        """Idempotent upsert of a framework entity."""
        await self._semantic_store.upsert_entity(
            tenant_id=self._customer_id,
            entity_type="framework",
            external_id=framework.external_id,
            properties=framework.properties(),
        )

    async def upsert_control(self, control: ControlEntity) -> None:
        """Idempotent upsert of a control entity."""
        await self._semantic_store.upsert_entity(
            tenant_id=self._customer_id,
            entity_type="control",
            external_id=control.external_id,
            properties=control.properties(),
        )


__all__ = ["KnowledgeGraphWriter"]
