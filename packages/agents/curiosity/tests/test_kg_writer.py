"""Tests — `curiosity.kg_writer` (Task 8 half).

Mocked SemanticStore (no live Postgres). Verifies:

1. ``upsert_hypothesis`` calls ``SemanticStore.upsert_entity`` with
   ``entity_type="hypothesis"`` and the customer:run:idx external_id.
2. tenant_id == writer.customer_id on every call.
3. Cross-tenant writes rejected at the writer boundary.
4. ``upsert_hypotheses`` top-level helper:
   - No-op-with-log when ``semantic_store=None`` (Q5 default).
   - No-op-with-log when ``entities=[]``.
   - Writes all entities when both are present.
   - Mixed-customer batches rejected (later entry trips the
     writer's cross-tenant guard).
5. Idempotent re-upsert uses the same composite key.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from charter.memory.semantic import SemanticStore
from curiosity.entities import HypothesisEntity
from curiosity.kg_writer import KnowledgeGraphWriter, upsert_hypotheses

_VALID_ULID = "01J7M3X9Z1K8RPVQNH2T8DBHFZ"


def _make_semantic_store() -> SemanticStore:
    entity_ids: dict[tuple[str, str], str] = {}

    async def fake_upsert_entity(
        *,
        tenant_id: str,
        entity_type: str,
        external_id: str,
        properties: dict[str, Any] | None = None,
    ) -> str:
        del tenant_id, properties
        key = (entity_type, external_id)
        if key not in entity_ids:
            entity_ids[key] = f"ent_{entity_type}_{len(entity_ids)}"
        return entity_ids[key]

    store = AsyncMock(spec=SemanticStore)
    store.upsert_entity.side_effect = fake_upsert_entity
    return cast(SemanticStore, store)


def _entity(**overrides: object) -> HypothesisEntity:
    defaults: dict[str, object] = {
        "customer_id": "acme",
        "run_id": "run-1",
        "hypothesis_idx": 0,
        "claim_id": _VALID_ULID,
        "statement": "Region us-east-1 appears under-scanned.",
        "target_agent": "data_security",
        "cited_region": "us-east-1",
        "emitted_at": datetime(2026, 5, 21, 12, 0, tzinfo=UTC),
    }
    defaults.update(overrides)
    return HypothesisEntity(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# KnowledgeGraphWriter direct usage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_uses_hypothesis_entity_type() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    await writer.upsert_hypothesis(_entity())

    store.upsert_entity.assert_awaited_once()
    call = store.upsert_entity.await_args.kwargs
    assert call["entity_type"] == "hypothesis"


@pytest.mark.asyncio
async def test_upsert_uses_customer_run_idx_external_id() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="contoso")
    await writer.upsert_hypothesis(_entity(customer_id="contoso", run_id="r99", hypothesis_idx=2))

    call = store.upsert_entity.await_args.kwargs
    assert call["external_id"] == "contoso:r99:2"


@pytest.mark.asyncio
async def test_writer_customer_id_propagates_as_tenant_id() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    await writer.upsert_hypothesis(_entity())

    call = store.upsert_entity.await_args.kwargs
    assert call["tenant_id"] == "acme"


@pytest.mark.asyncio
async def test_cross_tenant_write_rejected() -> None:
    """Writer.customer_id != entity.customer_id -> ValueError."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    entity = _entity(customer_id="contoso", run_id="r1")

    with pytest.raises(ValueError, match="customer_id"):
        await writer.upsert_hypothesis(entity)
    store.upsert_entity.assert_not_awaited()


@pytest.mark.asyncio
async def test_idempotent_re_upsert_uses_same_key() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    entity = _entity()

    await writer.upsert_hypothesis(entity)
    await writer.upsert_hypothesis(entity)

    assert store.upsert_entity.await_count == 2
    first = store.upsert_entity.await_args_list[0].kwargs
    second = store.upsert_entity.await_args_list[1].kwargs
    assert first["tenant_id"] == second["tenant_id"]
    assert first["entity_type"] == second["entity_type"]
    assert first["external_id"] == second["external_id"]


# ---------------------------------------------------------------------------
# Top-level helper (Q5 single-tenant default + batch)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_helper_no_op_when_store_none(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="curiosity.kg_writer"):
        await upsert_hypotheses(semantic_store=None, entities=[_entity()])
    assert any("skipped" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_helper_no_op_when_empty_entities(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = _make_semantic_store()
    with caplog.at_level(logging.INFO, logger="curiosity.kg_writer"):
        await upsert_hypotheses(semantic_store=store, entities=[])
    assert any("no entities" in rec.message for rec in caplog.records)
    store.upsert_entity.assert_not_awaited()


@pytest.mark.asyncio
async def test_helper_writes_each_entity_in_batch() -> None:
    store = _make_semantic_store()
    entities = [
        _entity(hypothesis_idx=0),
        _entity(hypothesis_idx=1, claim_id="01J7M3X9Z1K8RPVQNH2T8DBHG0"),
        _entity(hypothesis_idx=2, claim_id="01J7M3X9Z1K8RPVQNH2T8DBHG1"),
    ]
    await upsert_hypotheses(semantic_store=store, entities=entities)

    assert store.upsert_entity.await_count == 3
    external_ids = {call.kwargs["external_id"] for call in store.upsert_entity.await_args_list}
    assert external_ids == {"acme:run-1:0", "acme:run-1:1", "acme:run-1:2"}


@pytest.mark.asyncio
async def test_helper_propagates_customer_id_as_tenant() -> None:
    store = _make_semantic_store()
    entities = [_entity(customer_id="customer-X")]
    await upsert_hypotheses(semantic_store=store, entities=entities)
    assert store.upsert_entity.await_args.kwargs["tenant_id"] == "customer-X"


@pytest.mark.asyncio
async def test_helper_rejects_mixed_customer_batch() -> None:
    """Batch with entities from different tenants -> later entry
    trips the writer's cross-tenant guard. v0.1 forbids mixed
    batches (the driver always builds single-customer runs)."""
    store = _make_semantic_store()
    entities = [
        _entity(customer_id="acme", hypothesis_idx=0),
        _entity(customer_id="contoso", hypothesis_idx=1),  # different tenant
    ]
    with pytest.raises(ValueError, match="customer_id"):
        await upsert_hypotheses(semantic_store=store, entities=entities)
    # First entity wrote; second tripped the guard.
    assert store.upsert_entity.await_count == 1
