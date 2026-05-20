"""Tests — ``threat_intel.kg_writer`` (mocked SemanticStore).

Task 6 (kg_writer half). Mirrors cloud-posture's ``test_kg_writer.py``
shape — uses ``AsyncMock(spec=SemanticStore)`` to verify the writer's
upsert plumbing without a live database. Verifies:

1. Each upsert_* method calls ``SemanticStore.upsert_entity`` with the
   right ``entity_type`` (``ioc`` / ``cve`` / ``ttp``) and ``external_id``.
2. The properties dict has the expected shape.
3. The writer's ``customer_id`` propagates as ``tenant_id`` on every
   call.
4. Idempotency: re-upserting the same logical entity uses the same key.

No live Postgres; pure mocked SemanticStore.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from charter.memory import SemanticStore
from threat_intel.entities import CveEntity, IocEntity, TechniqueEntity
from threat_intel.kg_writer import KnowledgeGraphWriter
from threat_intel.schemas import IocType


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


# ---------------------------------------------------------------------------
# IOC upsert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_ioc_calls_substrate_with_ioc_entity_type() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    ioc = IocEntity(
        ioc_type=IocType.IP,
        value="1.2.3.4",
        first_seen=datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=datetime(2024, 1, 2, tzinfo=UTC),
        source_feed="abuse.ch",
    )
    await writer.upsert_ioc(ioc)

    mock_store = cast(AsyncMock, store)
    mock_store.upsert_entity.assert_awaited_once()
    kwargs = mock_store.upsert_entity.await_args.kwargs
    assert kwargs["tenant_id"] == "acme"
    assert kwargs["entity_type"] == "ioc"
    assert kwargs["external_id"] == "ip:1.2.3.4"
    assert kwargs["properties"]["ioc_type"] == "ip"
    assert kwargs["properties"]["value"] == "1.2.3.4"
    assert kwargs["properties"]["source_feed"] == "abuse.ch"


@pytest.mark.asyncio
async def test_upsert_ioc_external_id_encodes_type_and_value() -> None:
    """IP and domain with same value get distinct external_ids in the substrate."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    ip = IocEntity(
        ioc_type=IocType.IP,
        value="x.example",
        first_seen=datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=datetime(2024, 1, 1, tzinfo=UTC),
        source_feed="x",
    )
    domain = IocEntity(
        ioc_type=IocType.DOMAIN,
        value="x.example",
        first_seen=datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=datetime(2024, 1, 1, tzinfo=UTC),
        source_feed="x",
    )
    await writer.upsert_ioc(ip)
    await writer.upsert_ioc(domain)

    mock_store = cast(AsyncMock, store)
    external_ids = [call.kwargs["external_id"] for call in mock_store.upsert_entity.await_args_list]
    assert "ip:x.example" in external_ids
    assert "domain:x.example" in external_ids


@pytest.mark.asyncio
async def test_upsert_ioc_idempotent_under_same_key() -> None:
    """Re-upserting the same IOC reuses the substrate's idempotent key."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    ioc = IocEntity(
        ioc_type=IocType.DOMAIN,
        value="evil.example",
        first_seen=datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=datetime(2024, 1, 1, tzinfo=UTC),
        source_feed="x",
    )
    await writer.upsert_ioc(ioc)
    await writer.upsert_ioc(ioc)
    await writer.upsert_ioc(ioc)

    mock_store = cast(AsyncMock, store)
    # The writer calls upsert_entity once per upsert_ioc call — the
    # substrate (real or mocked here) collapses by (tenant, type,
    # external_id). All three calls use the same external_id.
    assert mock_store.upsert_entity.await_count == 3
    external_ids = {call.kwargs["external_id"] for call in mock_store.upsert_entity.await_args_list}
    assert external_ids == {"domain:evil.example"}


# ---------------------------------------------------------------------------
# CVE upsert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_cve_calls_substrate_with_cve_entity_type() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    cve = CveEntity(
        cve_id="CVE-2024-12345",
        cvss_v3_score=9.8,
        cvss_v3_severity="CRITICAL",
        kev_listed=True,
        kev_added_date=date(2024, 1, 15),
        description="Critical RCE",
    )
    await writer.upsert_cve(cve)

    mock_store = cast(AsyncMock, store)
    mock_store.upsert_entity.assert_awaited_once()
    kwargs = mock_store.upsert_entity.await_args.kwargs
    assert kwargs["tenant_id"] == "acme"
    assert kwargs["entity_type"] == "cve"
    assert kwargs["external_id"] == "CVE-2024-12345"
    assert kwargs["properties"]["cve_id"] == "CVE-2024-12345"
    assert kwargs["properties"]["cvss_v3_score"] == 9.8
    assert kwargs["properties"]["kev_listed"] is True
    assert kwargs["properties"]["kev_added_date"] == "2024-01-15"


@pytest.mark.asyncio
async def test_upsert_cve_idempotent_under_same_cve_id() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    cve = CveEntity(cve_id="CVE-2024-12345")
    await writer.upsert_cve(cve)
    await writer.upsert_cve(cve)

    mock_store = cast(AsyncMock, store)
    assert mock_store.upsert_entity.await_count == 2
    external_ids = {call.kwargs["external_id"] for call in mock_store.upsert_entity.await_args_list}
    assert external_ids == {"CVE-2024-12345"}


# ---------------------------------------------------------------------------
# Technique upsert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_technique_calls_substrate_with_ttp_entity_type() -> None:
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    t = TechniqueEntity(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactics=["execution"],
        platforms=["Linux", "Windows"],
    )
    await writer.upsert_technique(t)

    mock_store = cast(AsyncMock, store)
    mock_store.upsert_entity.assert_awaited_once()
    kwargs = mock_store.upsert_entity.await_args.kwargs
    assert kwargs["tenant_id"] == "acme"
    assert kwargs["entity_type"] == "ttp"
    assert kwargs["external_id"] == "T1059"
    assert kwargs["properties"]["tactics"] == ["execution"]
    assert kwargs["properties"]["platforms"] == ["Linux", "Windows"]


@pytest.mark.asyncio
async def test_upsert_subtechnique_distinct_external_id() -> None:
    """Sub-technique uses dotted-id; substrate sees it as a distinct entity."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="acme")
    parent = TechniqueEntity(technique_id="T1059", name="Command Interpreter")
    sub = TechniqueEntity(
        technique_id="T1059.003",
        name="Windows Command Shell",
        is_subtechnique=True,
    )
    await writer.upsert_technique(parent)
    await writer.upsert_technique(sub)

    mock_store = cast(AsyncMock, store)
    external_ids = {call.kwargs["external_id"] for call in mock_store.upsert_entity.await_args_list}
    assert external_ids == {"T1059", "T1059.003"}


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_writer_propagates_customer_id_as_tenant_id() -> None:
    """The writer's ``customer_id`` lands as ``tenant_id`` on every substrate call."""
    store = _make_semantic_store()
    writer = KnowledgeGraphWriter(store, customer_id="contoso")
    cve = CveEntity(cve_id="CVE-2024-12345")
    await writer.upsert_cve(cve)

    mock_store = cast(AsyncMock, store)
    kwargs = mock_store.upsert_entity.await_args.kwargs
    assert kwargs["tenant_id"] == "contoso"


@pytest.mark.asyncio
async def test_distinct_customer_ids_keep_substrate_calls_separate() -> None:
    """Two writers on different ``customer_id``s pass distinct ``tenant_id`` values."""
    store = _make_semantic_store()
    writer_a = KnowledgeGraphWriter(store, customer_id="acme")
    writer_b = KnowledgeGraphWriter(store, customer_id="contoso")
    cve = CveEntity(cve_id="CVE-2024-12345")
    await writer_a.upsert_cve(cve)
    await writer_b.upsert_cve(cve)

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
    ioc = IocEntity(
        ioc_type=IocType.IP,
        value="1.2.3.4",
        first_seen=datetime(2024, 1, 1, tzinfo=UTC),
        last_seen=datetime(2024, 1, 1, tzinfo=UTC),
        source_feed="x",
    )
    cve = CveEntity(cve_id="CVE-2024-12345")
    technique = TechniqueEntity(technique_id="T1059", name="x")
    await writer.upsert_ioc(ioc)
    await writer.upsert_cve(cve)
    await writer.upsert_technique(technique)

    mock_store = cast(AsyncMock, store)
    entity_types = [call.kwargs["entity_type"] for call in mock_store.upsert_entity.await_args_list]
    assert entity_types == ["ioc", "cve", "ttp"]
