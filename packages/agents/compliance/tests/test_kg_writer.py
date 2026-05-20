"""Tests — ``compliance.kg_writer`` (mocked SemanticStore).

Task 5 (kg_writer half). Uses ``AsyncMock(spec=SemanticStore)`` to
verify the writer's upsert plumbing without a live database. Verifies:

1. ``upsert_framework`` calls ``SemanticStore.upsert_entity`` with
   ``entity_type="framework"`` and the framework value as external_id.
2. ``upsert_control`` calls ``SemanticStore.upsert_entity`` with
   ``entity_type="control"`` and ``<framework>:<control_id>`` as
   external_id.
3. The writer's ``customer_id`` propagates as ``tenant_id`` on every
   call.
4. Idempotency: re-upserting the same logical entity uses the same key.

No live Postgres; pure mocked SemanticStore.
"""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from charter.memory import SemanticStore
from compliance.entities import ControlEntity, FrameworkEntity
from compliance.kg_writer import KnowledgeGraphWriter
from compliance.schemas import ComplianceFramework, ControlLevel


def _make_semantic_store() -> SemanticStore:
    """Return an ``AsyncMock(spec=SemanticStore)`` that returns deterministic
    entity_ids memoized by ``(entity_type, external_id)``.
    """
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


def _framework() -> FrameworkEntity:
    return FrameworkEntity(
        framework=ComplianceFramework.CIS_AWS_V3,
        version="3.0.0",
        name="CIS AWS Foundations Benchmark v3.0",
    )


def _control(control_id: str = "1.1") -> ControlEntity:
    return ControlEntity(
        framework=ComplianceFramework.CIS_AWS_V3,
        control_id=control_id,
        name="Root user MFA",
        level=ControlLevel.LEVEL_1,
    )


# ---------------------------------------------------------------------------
# upsert_framework
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_framework_uses_framework_entity_type() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    await writer.upsert_framework(_framework())

    mock_store = cast(AsyncMock, store)
    mock_store.upsert_entity.assert_awaited_once()
    kwargs = mock_store.upsert_entity.await_args.kwargs
    assert kwargs["tenant_id"] == "acme"
    assert kwargs["entity_type"] == "framework"
    assert kwargs["external_id"] == "cis_aws_v3"
    assert kwargs["properties"]["version"] == "3.0.0"


@pytest.mark.asyncio
async def test_upsert_framework_idempotent_under_same_key() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    await writer.upsert_framework(_framework())
    await writer.upsert_framework(_framework())

    mock_store = cast(AsyncMock, store)
    # The writer calls upsert_entity once per upsert_framework call —
    # substrate-level dedup collapses by (tenant, type, external_id).
    assert mock_store.upsert_entity.await_count == 2
    external_ids = {call.kwargs["external_id"] for call in mock_store.upsert_entity.await_args_list}
    assert external_ids == {"cis_aws_v3"}


# ---------------------------------------------------------------------------
# upsert_control
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_control_uses_control_entity_type() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    await writer.upsert_control(_control("1.1"))

    mock_store = cast(AsyncMock, store)
    mock_store.upsert_entity.assert_awaited_once()
    kwargs = mock_store.upsert_entity.await_args.kwargs
    assert kwargs["tenant_id"] == "acme"
    assert kwargs["entity_type"] == "control"
    assert kwargs["external_id"] == "cis_aws_v3:1.1"
    assert kwargs["properties"]["control_id"] == "1.1"
    assert kwargs["properties"]["level"] == "level_1"


@pytest.mark.asyncio
async def test_upsert_control_external_id_combines_framework_and_control_id(
    tmp_path: object,
) -> None:
    del tmp_path
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    await writer.upsert_control(_control("1.1"))
    await writer.upsert_control(_control("2.1.5"))

    mock_store = cast(AsyncMock, store)
    external_ids = [call.kwargs["external_id"] for call in mock_store.upsert_entity.await_args_list]
    assert "cis_aws_v3:1.1" in external_ids
    assert "cis_aws_v3:2.1.5" in external_ids


@pytest.mark.asyncio
async def test_upsert_control_idempotent_under_same_key() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    await writer.upsert_control(_control("1.1"))
    await writer.upsert_control(_control("1.1"))
    await writer.upsert_control(_control("1.1"))

    mock_store = cast(AsyncMock, store)
    assert mock_store.upsert_entity.await_count == 3
    external_ids = {call.kwargs["external_id"] for call in mock_store.upsert_entity.await_args_list}
    assert external_ids == {"cis_aws_v3:1.1"}


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_writer_propagates_customer_id_as_tenant_id() -> None:
    """The writer's ``customer_id`` lands as ``tenant_id`` on every substrate call."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="contoso")
    await writer.upsert_control(_control())

    mock_store = cast(AsyncMock, store)
    kwargs = mock_store.upsert_entity.await_args.kwargs
    assert kwargs["tenant_id"] == "contoso"


@pytest.mark.asyncio
async def test_distinct_customer_ids_keep_substrate_calls_separate() -> None:
    """Two writers on different ``customer_id``s pass distinct ``tenant_id`` values."""
    store = _make_semantic_store()
    writer_a = KnowledgeGraphWriter(store, customer_id="acme")
    writer_b = KnowledgeGraphWriter(store, customer_id="contoso")
    await writer_a.upsert_control(_control())
    await writer_b.upsert_control(_control())

    mock_store = cast(AsyncMock, store)
    tenant_ids = [call.kwargs["tenant_id"] for call in mock_store.upsert_entity.await_args_list]
    assert tenant_ids == ["acme", "contoso"]


# ---------------------------------------------------------------------------
# Mixed-entity-type runs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mixed_entity_types_use_correct_entity_type_per_call() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    await writer.upsert_framework(_framework())
    await writer.upsert_control(_control("1.1"))
    await writer.upsert_control(_control("1.5"))

    mock_store = cast(AsyncMock, store)
    entity_types = [call.kwargs["entity_type"] for call in mock_store.upsert_entity.await_args_list]
    assert entity_types == ["framework", "control", "control"]
