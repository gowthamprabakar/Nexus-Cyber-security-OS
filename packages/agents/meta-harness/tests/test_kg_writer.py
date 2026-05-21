"""Tests — `meta_harness.kg_writer` (Task 8 half).

Mocked SemanticStore (no live Postgres). 9 tests verifying:

1.  ``upsert_scorecard`` calls ``SemanticStore.upsert_entity`` with
    ``entity_type="agent_scorecard"`` + the
    ``customer:run:agent`` external_id.
2.  Writer.customer_id propagates as tenant_id on every call.
3.  Cross-tenant scorecard write rejected at the writer boundary.
4.  ``upsert_scorecards`` top-level helper:
    a) No-op-with-log when ``semantic_store=None`` (Q5 default).
    b) No-op-with-log when ``entities=[]``.
    c) Writes all entities when both are present.
    d) Mixed-customer batch rejected at the writer boundary.
5.  ``upsert_ab_result`` writes one ab_comparison_result entity.
6.  ``upsert_ab_result`` no-op-with-log when entity=None.
7.  ``upsert_ab_result`` no-op-with-log when semantic_store=None.
8.  ``upsert_ab_result`` cross-tenant rejected at writer boundary.
9.  Idempotent re-upsert uses the same composite key.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from charter.memory.semantic import SemanticStore
from meta_harness.entities import ABComparisonResult, AgentScorecard
from meta_harness.kg_writer import (
    KnowledgeGraphWriter,
    upsert_ab_result,
    upsert_scorecards,
)

_NOW = datetime(2026, 5, 21, 12, 0, tzinfo=UTC)


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


def _scorecard(**overrides: object) -> AgentScorecard:
    defaults: dict[str, object] = {
        "customer_id": "acme",
        "run_id": "r1",
        "agent_id": "cloud_posture",
        "total_cases": 10,
        "passed": 9,
        "failed": 1,
        "pass_rate": 0.9,
        "evaluated_at": _NOW,
    }
    defaults.update(overrides)
    return AgentScorecard(**defaults)  # type: ignore[arg-type]


def _ab_result(**overrides: object) -> ABComparisonResult:
    defaults: dict[str, object] = {
        "customer_id": "acme",
        "run_id": "r1",
        "agent_id": "cloud_posture",
        "variant_a_path": "/nlah/a",
        "variant_b_path": "/nlah/b",
        "variant_a_pass_rate": 0.9,
        "variant_b_pass_rate": 0.85,
        "byte_equal": False,
        "evaluated_at": _NOW,
    }
    defaults.update(overrides)
    return ABComparisonResult(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Writer direct usage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_scorecard_uses_agent_scorecard_entity_type() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    await writer.upsert_scorecard(_scorecard())

    call = store.upsert_entity.await_args.kwargs
    assert call["entity_type"] == "agent_scorecard"
    assert call["external_id"] == "acme:r1:cloud_posture"


@pytest.mark.asyncio
async def test_writer_customer_id_propagates_as_tenant_id() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="contoso")
    await writer.upsert_scorecard(_scorecard(customer_id="contoso", run_id="r99"))
    call = store.upsert_entity.await_args.kwargs
    assert call["tenant_id"] == "contoso"


@pytest.mark.asyncio
async def test_cross_tenant_scorecard_rejected() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    entity = _scorecard(customer_id="contoso")
    with pytest.raises(ValueError, match="customer_id"):
        await writer.upsert_scorecard(entity)
    store.upsert_entity.assert_not_awaited()


@pytest.mark.asyncio
async def test_idempotent_re_upsert_uses_same_key() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    entity = _scorecard()
    await writer.upsert_scorecard(entity)
    await writer.upsert_scorecard(entity)
    assert store.upsert_entity.await_count == 2
    first = store.upsert_entity.await_args_list[0].kwargs
    second = store.upsert_entity.await_args_list[1].kwargs
    assert first["external_id"] == second["external_id"]
    assert first["entity_type"] == second["entity_type"]


# ---------------------------------------------------------------------------
# upsert_scorecards top-level helper
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_scorecards_no_op_when_store_none(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="meta_harness.kg_writer"):
        await upsert_scorecards(semantic_store=None, entities=[_scorecard()])
    assert any("skipped" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_upsert_scorecards_no_op_when_empty(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = _make_semantic_store()
    with caplog.at_level(logging.INFO, logger="meta_harness.kg_writer"):
        await upsert_scorecards(semantic_store=store, entities=[])
    assert any("no entities" in rec.message for rec in caplog.records)
    store.upsert_entity.assert_not_awaited()


@pytest.mark.asyncio
async def test_upsert_scorecards_writes_each_in_batch() -> None:
    store = _make_semantic_store()
    entities = [
        _scorecard(agent_id="a"),
        _scorecard(agent_id="b"),
        _scorecard(agent_id="c"),
    ]
    await upsert_scorecards(semantic_store=store, entities=entities)
    assert store.upsert_entity.await_count == 3
    external_ids = {call.kwargs["external_id"] for call in store.upsert_entity.await_args_list}
    assert external_ids == {"acme:r1:a", "acme:r1:b", "acme:r1:c"}


@pytest.mark.asyncio
async def test_upsert_scorecards_rejects_mixed_customer_batch() -> None:
    """Later entry with different customer_id trips cross-tenant guard."""
    store = _make_semantic_store()
    entities = [
        _scorecard(customer_id="acme", agent_id="a"),
        _scorecard(customer_id="contoso", agent_id="b"),
    ]
    with pytest.raises(ValueError, match="customer_id"):
        await upsert_scorecards(semantic_store=store, entities=entities)
    assert store.upsert_entity.await_count == 1


# ---------------------------------------------------------------------------
# upsert_ab_result top-level helper
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_ab_result_writes_one_entity() -> None:
    store = _make_semantic_store()
    await upsert_ab_result(semantic_store=store, entity=_ab_result())
    call = store.upsert_entity.await_args.kwargs
    assert call["entity_type"] == "ab_comparison_result"
    assert call["external_id"] == "acme:r1:cloud_posture:/nlah/a:/nlah/b"


@pytest.mark.asyncio
async def test_upsert_ab_result_no_op_when_entity_none(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = _make_semantic_store()
    with caplog.at_level(logging.INFO, logger="meta_harness.kg_writer"):
        await upsert_ab_result(semantic_store=store, entity=None)
    assert any("no A/B" in rec.message for rec in caplog.records)
    store.upsert_entity.assert_not_awaited()


@pytest.mark.asyncio
async def test_upsert_ab_result_no_op_when_store_none(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="meta_harness.kg_writer"):
        await upsert_ab_result(semantic_store=None, entity=_ab_result())
    assert any("skipped" in rec.message for rec in caplog.records)
