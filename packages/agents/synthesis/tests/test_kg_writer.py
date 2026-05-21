"""Tests — ``synthesis.kg_writer`` (Task 8 half).

Mocked SemanticStore (no live Postgres). Verifies:

1. ``upsert_synthesis_report`` calls ``SemanticStore.upsert_entity``
   with ``entity_type="synthesis_report"`` and ``<customer_id>:
   <run_id>`` as external_id.
2. The writer's ``customer_id`` propagates as ``tenant_id`` on the
   upsert call.
3. The top-level helper ``upsert_synthesis_report`` is a no-op when
   ``semantic_store=None`` (single-tenant v0.1 default per Q5).
4. Cross-tenant writes (entity.customer_id != writer.customer_id)
   are rejected as defence-in-depth.
5. Idempotency: re-upserting the same logical entity uses the same
   composite key.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from charter.memory.semantic import SemanticStore
from synthesis.entities import SynthesisReportEntity
from synthesis.kg_writer import KnowledgeGraphWriter, upsert_synthesis_report


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


def _entity(**overrides: object) -> SynthesisReportEntity:
    defaults: dict[str, object] = {
        "customer_id": "acme",
        "run_id": "run-1",
        "section_count": 3,
        "executive_summary_paragraph": "Summary of the scan.",
        "total_cited_findings": 5,
        "scan_started_at": datetime(2026, 5, 21, 12, 0, tzinfo=UTC),
        "scan_completed_at": datetime(2026, 5, 21, 12, 5, tzinfo=UTC),
        "review_retries": 0,
    }
    defaults.update(overrides)
    return SynthesisReportEntity(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# KnowledgeGraphWriter direct usage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_uses_synthesis_report_entity_type() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    await writer.upsert_synthesis_report(_entity())

    store.upsert_entity.assert_awaited_once()
    call_kwargs = store.upsert_entity.await_args.kwargs
    assert call_kwargs["entity_type"] == "synthesis_report"


@pytest.mark.asyncio
async def test_upsert_uses_customer_run_pair_as_external_id() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="contoso")
    await writer.upsert_synthesis_report(_entity(customer_id="contoso", run_id="r99"))

    call_kwargs = store.upsert_entity.await_args.kwargs
    assert call_kwargs["external_id"] == "contoso:r99"


@pytest.mark.asyncio
async def test_writer_customer_id_propagates_as_tenant_id() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    await writer.upsert_synthesis_report(_entity())

    call_kwargs = store.upsert_entity.await_args.kwargs
    assert call_kwargs["tenant_id"] == "acme"


@pytest.mark.asyncio
async def test_upsert_passes_full_property_dict() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    entity = _entity(section_count=7, total_cited_findings=12)
    await writer.upsert_synthesis_report(entity)

    props = store.upsert_entity.await_args.kwargs["properties"]
    assert props["section_count"] == 7
    assert props["total_cited_findings"] == 12


@pytest.mark.asyncio
async def test_idempotent_re_upsert_uses_same_composite_key() -> None:
    """Calling upsert twice with the same logical entity hits the
    same SemanticStore composite key both times."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    entity = _entity()

    await writer.upsert_synthesis_report(entity)
    await writer.upsert_synthesis_report(entity)

    assert store.upsert_entity.await_count == 2
    first = store.upsert_entity.await_args_list[0].kwargs
    second = store.upsert_entity.await_args_list[1].kwargs
    assert first["tenant_id"] == second["tenant_id"]
    assert first["entity_type"] == second["entity_type"]
    assert first["external_id"] == second["external_id"]


@pytest.mark.asyncio
async def test_cross_tenant_write_rejected() -> None:
    """Writer.customer_id != entity.customer_id -> ValueError."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    entity = _entity(customer_id="contoso", run_id="r1")

    with pytest.raises(ValueError, match="customer_id"):
        await writer.upsert_synthesis_report(entity)
    store.upsert_entity.assert_not_awaited()


# ---------------------------------------------------------------------------
# Top-level helper (single-tenant default)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_top_level_helper_no_op_when_store_none(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Q5 single-tenant default: semantic_store=None -> skip + log."""
    with caplog.at_level(logging.INFO, logger="synthesis.kg_writer"):
        await upsert_synthesis_report(semantic_store=None, entity=_entity())

    assert any("skipped" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_top_level_helper_writes_when_store_present() -> None:
    store = _make_semantic_store()
    await upsert_synthesis_report(semantic_store=store, entity=_entity())

    store.upsert_entity.assert_awaited_once()
    assert store.upsert_entity.await_args.kwargs["entity_type"] == "synthesis_report"


@pytest.mark.asyncio
async def test_top_level_helper_propagates_entity_customer_id_as_tenant() -> None:
    """The helper instantiates the writer with entity.customer_id so
    multi-tenant tenant-RLS works once SET LOCAL $1 fix lands."""
    store = _make_semantic_store()
    await upsert_synthesis_report(semantic_store=store, entity=_entity(customer_id="customer-X"))

    assert store.upsert_entity.await_args.kwargs["tenant_id"] == "customer-X"
