"""Knowledge-graph writer for D.13 synthesis reports.

Per Q5 of the D.13 v0.1 plan, synthesis entities are persisted to
the platform's Postgres ``SemanticStore`` using the same pattern
shipped in F.3 v0.1.5 + reused in D.5 / D.6 / D.8.

**Single-tenant ``semantic_store=None`` opt-in default.** Per the
Path-B operating rule §11.1: multi-tenant production blocks on the
future SET LOCAL ``$1`` tenant-RLS substrate-fix plan. v0.1 keeps
the agent driver path that constructs the writer guarded — when
``semantic_store`` is None at the agent boundary, the writer is
never instantiated and no SemanticStore writes happen.

The writer is **side-effect-only** (returns ``None``); the upsert
is idempotent per the substrate's composite key
``(tenant_id, entity_type, external_id)``.

Q6 reminder: the executive_summary paragraph carried in the entity
has already passed through Stage 4 REVIEW. The writer is a thin
serialiser; it does no further Q6 validation.
"""

from __future__ import annotations

import logging

from charter.memory.semantic import SemanticStore

from synthesis.entities import SynthesisReportEntity

_LOG = logging.getLogger(__name__)

_ENTITY_TYPE = "synthesis_report"


class KnowledgeGraphWriter:
    """Customer-scoped writer for synthesis-report entities.

    Mirrors F.3 / D.5 / D.6 / D.8's ``KnowledgeGraphWriter`` shape:
    ``async`` methods, side-effect-only. The substrate's composite
    key for entities is ``(tenant_id, entity_type, external_id)``;
    the writer's ``upsert_synthesis_report`` method produces the
    external_id from the entity's identifying fields
    (``<customer_id>:<run_id>``).
    """

    def __init__(self, semantic_store: SemanticStore, customer_id: str) -> None:
        self._semantic_store = semantic_store
        self._customer_id = customer_id

    async def upsert_synthesis_report(self, entity: SynthesisReportEntity) -> None:
        """Idempotent upsert of a synthesis-report entity.

        The entity's ``customer_id`` MUST match the writer's
        ``customer_id`` — cross-tenant writes are rejected at this
        boundary as a defence-in-depth check (the SemanticStore
        itself uses ``tenant_id`` for RLS; this is a second line of
        defence in case the writer is mis-wired).
        """
        if entity.customer_id != self._customer_id:
            raise ValueError(
                f"entity.customer_id {entity.customer_id!r} does not match "
                f"writer.customer_id {self._customer_id!r}"
            )
        await self._semantic_store.upsert_entity(
            tenant_id=self._customer_id,
            entity_type=_ENTITY_TYPE,
            external_id=entity.external_id,
            properties=entity.properties(),
        )


async def upsert_synthesis_report(
    *,
    semantic_store: SemanticStore | None,
    entity: SynthesisReportEntity,
) -> None:
    """Top-level helper: write a single entity, no-op when store=None.

    Per Q5, the single-tenant default is ``semantic_store=None`` and
    the caller (Task 9 driver) wires through a real store only when
    multi-tenant production becomes safe (post tenant-RLS substrate
    fix). When None, this helper logs the skip at INFO and returns
    cleanly.
    """
    if semantic_store is None:
        _LOG.info(
            "kg_writer.upsert_synthesis_report skipped: "
            "semantic_store=None (v0.1 single-tenant default); "
            "entity external_id=%s",
            entity.external_id,
        )
        return

    writer = KnowledgeGraphWriter(semantic_store=semantic_store, customer_id=entity.customer_id)
    await writer.upsert_synthesis_report(entity)


__all__ = [
    "KnowledgeGraphWriter",
    "upsert_synthesis_report",
]
