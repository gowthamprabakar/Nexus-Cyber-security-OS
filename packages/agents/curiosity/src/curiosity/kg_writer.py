"""Knowledge-graph writer for D.12 hypothesis claims.

Per Q5 of the D.12 v0.1 plan, hypothesis entities are persisted to
the platform's Postgres ``SemanticStore`` using the same pattern
shipped in F.3 v0.1.5 + reused in D.5 / D.6 / D.8 / D.13.

Unlike D.13 (one entity per run), D.12 emits **N entities per
run** — one per hypothesis. The top-level helper
``upsert_hypotheses`` accepts a list and writes each.

**Single-tenant ``semantic_store=None`` opt-in default.** Per the
Path-B operating rule §11.1: multi-tenant production blocks on the
future SET LOCAL ``$1`` tenant-RLS substrate-fix plan. v0.1 keeps
the agent driver path that constructs the writer guarded — when
``semantic_store`` is None at the agent boundary, the helper is a
no-op-with-log and no SemanticStore writes happen.

The writer is **side-effect-only**; the upsert is idempotent per
the substrate's composite key ``(tenant_id, entity_type,
external_id)``.

Q6 reminder: each hypothesis's text has already passed Stage 4
REVIEW so the persisted statement is guaranteed free of classifier-
shaped substrings. The writer is a thin serialiser; it does no
further Q6 validation.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from charter.memory.semantic import SemanticStore

from curiosity.entities import HypothesisEntity

_LOG = logging.getLogger(__name__)

_ENTITY_TYPE = "hypothesis"


class KnowledgeGraphWriter:
    """Customer-scoped writer for hypothesis entities.

    Mirrors F.3 / D.5 / D.6 / D.8 / D.13's ``KnowledgeGraphWriter``
    shape: ``async`` methods, side-effect-only. The substrate's
    composite key is ``(tenant_id, entity_type, external_id)``;
    the writer produces the external_id from the entity's
    identifying fields (``<customer_id>:<run_id>:<hypothesis_idx>``).
    """

    def __init__(self, semantic_store: SemanticStore, customer_id: str) -> None:
        self._semantic_store = semantic_store
        self._customer_id = customer_id

    async def upsert_hypothesis(self, entity: HypothesisEntity) -> None:
        """Idempotent upsert of one hypothesis entity.

        Cross-tenant defence-in-depth: rejects when the entity's
        customer_id differs from the writer's customer_id.
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


async def upsert_hypotheses(
    *,
    semantic_store: SemanticStore | None,
    entities: Sequence[HypothesisEntity],
) -> None:
    """Top-level helper: write a batch of hypothesis entities.

    No-op-with-log when ``semantic_store`` is None (Q5 single-tenant
    default) or when ``entities`` is empty. When a store is provided
    and entities are present, instantiates the writer with the
    first entity's ``customer_id`` and writes each entity in order.

    Per Q5, the writer's ``customer_id`` is taken from the first
    entity. Mixed-customer batches are forbidden: a later entity
    with a different ``customer_id`` raises a ``ValueError`` via
    the writer's cross-tenant guard.
    """
    if not entities:
        _LOG.info("kg_writer.upsert_hypotheses: no entities to persist")
        return

    if semantic_store is None:
        _LOG.info(
            "kg_writer.upsert_hypotheses skipped: semantic_store=None "
            "(v0.1 single-tenant default); would have persisted %d entities",
            len(entities),
        )
        return

    customer_id = entities[0].customer_id
    writer = KnowledgeGraphWriter(semantic_store=semantic_store, customer_id=customer_id)
    for entity in entities:
        await writer.upsert_hypothesis(entity)


__all__ = [
    "KnowledgeGraphWriter",
    "upsert_hypotheses",
]
