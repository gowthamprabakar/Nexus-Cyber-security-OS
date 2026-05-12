"""Tests for `charter.memory.models.AuditEventModel` (F.6 Task 2).

Extends the shared declarative `Base` with the `audit_events` table so
F.6 Audit Agent has a fast-query backing store independent of the
per-engine `episodes` audit emissions. Production contract:

1. The model is re-exported from `charter.memory` so consumers wire it
   via the same surface they wire `EpisodeModel` etc.
2. `Base.metadata.create_all` against aiosqlite materialises the table
   with every production index.
3. Column shape pins the OCSF 2007 wire format: `tenant_id` (26-char
   ULID), `correlation_id` (32-char ULID), `agent_id`, `action`,
   `payload` (JSONB-portable), `previous_hash` + `entry_hash` (64-char
   hex), `emitted_at`, `ingested_at`, `source`.
4. `(tenant_id, entry_hash)` is unique — Task 5's `AuditStore.ingest`
   relies on this for idempotent re-ingest.
5. Three production indexes: `(tenant_id, emitted_at DESC)`,
   `(tenant_id, action)`, `correlation_id`.
6. Tenant isolation is enforced by RLS in `0003_audit_events`
   (Task 3); the model itself just carries `tenant_id` as a
   leading column.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from charter.memory import AuditEventModel
from charter.memory.models import Base
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


@pytest_asyncio.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


_TENANT_A = "01HV0T0000000000000000TENA"
_TENANT_B = "01HV0T0000000000000000TENB"
_HEX64_A = "a" * 64
_HEX64_B = "b" * 64
_HEX64_C = "c" * 64


# ---------------------------- re-export -----------------------------------


def test_audit_event_model_is_reexported_from_charter_memory() -> None:
    import charter.memory as memory_pkg

    assert "AuditEventModel" in memory_pkg.__all__
    assert hasattr(memory_pkg, "AuditEventModel")


# ---------------------------- table metadata ------------------------------


def test_audit_events_table_present_in_base_metadata() -> None:
    assert "audit_events" in Base.metadata.tables


def test_audit_events_column_shape() -> None:
    table = Base.metadata.tables["audit_events"]
    expected = {
        "audit_event_id",
        "tenant_id",
        "correlation_id",
        "agent_id",
        "action",
        "payload",
        "previous_hash",
        "entry_hash",
        "emitted_at",
        "ingested_at",
        "source",
    }
    assert set(table.columns.keys()) == expected
    assert table.primary_key.columns.keys() == ["audit_event_id"]


# ---------------------------- indexes -------------------------------------


@pytest.mark.asyncio
async def test_audit_events_indexes_materialize_against_aiosqlite(
    engine: AsyncEngine,
) -> None:
    async with engine.connect() as conn:
        index_names = await conn.run_sync(
            lambda sync_conn: {
                idx["name"] for idx in inspect(sync_conn).get_indexes("audit_events")
            }
        )

    expected = {
        "ix_audit_events_tenant_emitted",
        "ix_audit_events_tenant_action",
        "ix_audit_events_correlation",
    }
    assert expected <= index_names


# ---------------------------- unique constraint ---------------------------


@pytest.mark.asyncio
async def test_audit_events_tenant_entry_hash_is_unique(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Idempotent ingest contract relies on this constraint."""
    now = datetime.now(UTC)
    async with session_factory.begin() as session:
        session.add(
            AuditEventModel(
                tenant_id=_TENANT_A,
                correlation_id="corr-1",
                agent_id="cloud_posture",
                action="finding.created",
                payload={"finding_id": "F-1"},
                previous_hash=_HEX64_A,
                entry_hash=_HEX64_B,
                emitted_at=now,
                source="jsonl:/var/log/audit.jsonl",
            )
        )

    with pytest.raises(IntegrityError):
        async with session_factory.begin() as session:
            session.add(
                AuditEventModel(
                    tenant_id=_TENANT_A,
                    correlation_id="corr-1",
                    agent_id="cloud_posture",
                    action="finding.created",
                    payload={"finding_id": "F-1"},
                    previous_hash=_HEX64_A,
                    entry_hash=_HEX64_B,  # same hash → must conflict
                    emitted_at=now,
                    source="jsonl:/var/log/audit.jsonl",
                )
            )


@pytest.mark.asyncio
async def test_audit_events_same_hash_distinct_tenants_is_allowed(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """The unique constraint is (tenant_id, entry_hash) — same hash across
    tenants is allowed (chains start at the same genesis).
    """
    now = datetime.now(UTC)
    async with session_factory.begin() as session:
        session.add(
            AuditEventModel(
                tenant_id=_TENANT_A,
                correlation_id="c",
                agent_id="a",
                action="x",
                payload={},
                previous_hash=_HEX64_A,
                entry_hash=_HEX64_C,
                emitted_at=now,
                source="jsonl",
            )
        )
        session.add(
            AuditEventModel(
                tenant_id=_TENANT_B,
                correlation_id="c",
                agent_id="a",
                action="x",
                payload={},
                previous_hash=_HEX64_A,
                entry_hash=_HEX64_C,  # same hash, different tenant
                emitted_at=now,
                source="jsonl",
            )
        )

    async with session_factory() as session:
        rows = (await session.execute(select(AuditEventModel))).scalars().all()
        assert len(rows) == 2


# ---------------------------- payload round-trip --------------------------


@pytest.mark.asyncio
async def test_audit_events_payload_round_trip(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    payload = {
        "nested": {"k": [1, 2, {"deep": "value"}]},
        "unicode": "🛡️ — em-dash",
        "boolean": True,
        "null": None,
    }
    now = datetime.now(UTC)
    async with session_factory.begin() as session:
        session.add(
            AuditEventModel(
                tenant_id=_TENANT_A,
                correlation_id="c",
                agent_id="a",
                action="x",
                payload=payload,
                previous_hash=_HEX64_A,
                entry_hash=_HEX64_B,
                emitted_at=now,
                source="jsonl",
            )
        )

    async with session_factory() as session:
        row = (await session.execute(select(AuditEventModel))).scalar_one()
        assert row.payload == payload


# ---------------------------- defaults ------------------------------------


@pytest.mark.asyncio
async def test_audit_events_ingested_at_defaults_to_now(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    now = datetime.now(UTC)
    async with session_factory.begin() as session:
        row = AuditEventModel(
            tenant_id=_TENANT_A,
            correlation_id="c",
            agent_id="a",
            action="x",
            payload={},
            previous_hash=_HEX64_A,
            entry_hash=_HEX64_B,
            emitted_at=now,
            source="jsonl",
        )
        session.add(row)
        await session.flush()
        assert row.ingested_at is not None
