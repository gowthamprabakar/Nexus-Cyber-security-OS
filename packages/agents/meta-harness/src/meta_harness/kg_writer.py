"""Knowledge-graph writer for A.4 Meta-Harness run output.

Per Q5 of the A.4 v0.1 plan, scorecards + A/B results are persisted
to the platform's Postgres ``SemanticStore`` using the same pattern
shipped in F.3 v0.1.5 + reused in D.5 / D.6 / D.8 / D.13 / D.12.

A.4 writes **two entity types** per run (per the Q1 emit directions):

- ``agent_scorecard`` — one entity per evaluated agent.
- ``ab_comparison_result`` — one entity per A/B run (only when the
  ``ab-compare`` subcommand is used).

**Single-tenant ``semantic_store=None`` opt-in default.** Per the
Path-B operating rule §11.1: multi-tenant production blocks on the
future SET LOCAL ``$1`` tenant-RLS substrate-fix plan. v0.1 keeps
the agent driver path that constructs the writer guarded — when
``semantic_store`` is None at the agent boundary, the top-level
helpers are no-ops-with-log and no SemanticStore writes happen.

**Idempotent** per the substrate's composite key
``(tenant_id, entity_type, external_id)``.

**Read-only contract (WI-4) preserved.** Writes happen here against
the platform's own SemanticStore — not against any agent's NLAH
directory. The NLAH-write deferral (Q-ARCH-3) is unaffected.

**Q-ARCH-2 reminder.** Persistence only; no fabric publish.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from charter.memory.semantic import SemanticStore

from meta_harness.entities import ABComparisonResult, AgentScorecard

_LOG = logging.getLogger(__name__)

_SCORECARD_ENTITY_TYPE = "agent_scorecard"
_AB_RESULT_ENTITY_TYPE = "ab_comparison_result"


class KnowledgeGraphWriter:
    """Customer-scoped writer for meta-harness entities.

    Mirrors the shape every prior agent ships: ``async`` methods,
    side-effect-only, cross-tenant rejection at the writer
    boundary.
    """

    def __init__(self, semantic_store: SemanticStore, customer_id: str) -> None:
        self._semantic_store = semantic_store
        self._customer_id = customer_id

    async def upsert_scorecard(self, entity: AgentScorecard) -> None:
        """Idempotent upsert of one AgentScorecard."""
        self._require_same_tenant(entity.customer_id)
        await self._semantic_store.upsert_entity(
            tenant_id=self._customer_id,
            entity_type=_SCORECARD_ENTITY_TYPE,
            external_id=entity.external_id,
            properties=entity.properties(),
        )

    async def upsert_ab_result(self, entity: ABComparisonResult) -> None:
        """Idempotent upsert of one ABComparisonResult."""
        self._require_same_tenant(entity.customer_id)
        await self._semantic_store.upsert_entity(
            tenant_id=self._customer_id,
            entity_type=_AB_RESULT_ENTITY_TYPE,
            external_id=entity.external_id,
            properties=entity.properties(),
        )

    def _require_same_tenant(self, entity_customer_id: str) -> None:
        if entity_customer_id != self._customer_id:
            raise ValueError(
                f"entity.customer_id {entity_customer_id!r} does not match "
                f"writer.customer_id {self._customer_id!r}"
            )


async def upsert_scorecards(
    *,
    semantic_store: SemanticStore | None,
    entities: Sequence[AgentScorecard],
) -> None:
    """Top-level helper: write a batch of AgentScorecard entities.

    No-op-with-log when ``semantic_store`` is None (Q5 single-tenant
    default) or ``entities`` is empty. When both are present,
    instantiates the writer with the first entity's ``customer_id``
    and writes each entity in order. Mixed-customer batches are
    forbidden — a later entity with a different ``customer_id``
    trips the writer's cross-tenant guard.
    """
    if not entities:
        _LOG.info("kg_writer.upsert_scorecards: no entities to persist")
        return
    if semantic_store is None:
        _LOG.info(
            "kg_writer.upsert_scorecards skipped: semantic_store=None "
            "(v0.1 single-tenant default); would have persisted %d entities",
            len(entities),
        )
        return

    customer_id = entities[0].customer_id
    writer = KnowledgeGraphWriter(semantic_store=semantic_store, customer_id=customer_id)
    for entity in entities:
        await writer.upsert_scorecard(entity)


async def upsert_ab_result(
    *,
    semantic_store: SemanticStore | None,
    entity: ABComparisonResult | None,
) -> None:
    """Top-level helper: write one ABComparisonResult.

    No-op-with-log when ``semantic_store`` is None or ``entity`` is
    None (the A/B subcommand wasn't invoked).
    """
    if entity is None:
        _LOG.info("kg_writer.upsert_ab_result: no A/B result to persist")
        return
    if semantic_store is None:
        _LOG.info(
            "kg_writer.upsert_ab_result skipped: semantic_store=None (v0.1 single-tenant default)"
        )
        return

    writer = KnowledgeGraphWriter(semantic_store=semantic_store, customer_id=entity.customer_id)
    await writer.upsert_ab_result(entity)


__all__ = [
    "KnowledgeGraphWriter",
    "upsert_ab_result",
    "upsert_scorecards",
]
