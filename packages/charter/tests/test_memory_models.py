"""Tests for `charter.memory.models` (F.5 Task 1).

Production-grade discipline: every test exercises real behavior against
an in-memory aiosqlite database. We assert table structure (column
types, nullability, FKs, ON DELETE CASCADE), index presence on the
dialect-portable indexes, **and** that real insert + query + delete
flows succeed end-to-end through an `AsyncSession`. No "import works"
placebo tests.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime

import pytest
import pytest_asyncio
from charter.memory import (
    EMBEDDING_DIM,
    Base,
    EntityModel,
    EpisodeModel,
    PlaybookModel,
    RelationshipModel,
)
from sqlalchemy import inspect, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

TENANT_A = "01HXYZTENANT0000000000000A"
TENANT_B = "01HXYZTENANT0000000000000B"


@pytest_asyncio.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


# ---------------------------- module-level surface ------------------------


def test_memory_module_reexports_only_existing_symbols() -> None:
    """Discipline gate — `__all__` in charter.memory matches what models.py defines.

    If a future task forward-declares a re-export of an unimplemented
    class, this test fails immediately.
    """
    import charter.memory as memory_pkg
    from charter.memory import models as models_mod

    for name in memory_pkg.__all__:
        assert hasattr(memory_pkg, name), (
            f"charter.memory.__all__ promises {name!r} but it isn't defined"
        )
        # Every re-export resolves to the real implementation in models.py.
        if name != "EMBEDDING_DIM":
            assert getattr(memory_pkg, name) is getattr(models_mod, name)


def test_embedding_dim_is_1536() -> None:
    """OpenAI text-embedding-3-small dim; FakeEmbeddingProvider (Task 4) inherits."""
    assert EMBEDDING_DIM == 1536


# ---------------------------- schema shape --------------------------------


def test_base_metadata_contains_exactly_four_tables() -> None:
    assert set(Base.metadata.tables) == {"episodes", "playbooks", "entities", "relationships"}


@pytest.mark.asyncio
async def test_episodes_table_columns(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        cols = await conn.run_sync(
            lambda sync_conn: {c["name"]: c for c in inspect(sync_conn).get_columns("episodes")}
        )

    assert {
        "episode_id",
        "tenant_id",
        "correlation_id",
        "agent_id",
        "action",
        "payload",
        "embedding",
        "emitted_at",
    } <= set(cols)
    assert cols["episode_id"]["primary_key"]
    assert not cols["tenant_id"]["nullable"]
    assert not cols["payload"]["nullable"]
    assert cols["embedding"]["nullable"]


@pytest.mark.asyncio
async def test_playbooks_table_columns_and_unique_constraint(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        cols = await conn.run_sync(
            lambda sync_conn: {c["name"]: c for c in inspect(sync_conn).get_columns("playbooks")}
        )
        uniques = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_unique_constraints("playbooks")
        )

    assert {"playbook_id", "tenant_id", "path", "version", "active", "body", "published_at"} <= set(
        cols
    )
    unique_cols = {tuple(sorted(u["column_names"])) for u in uniques}
    assert ("path", "tenant_id", "version") in unique_cols


@pytest.mark.asyncio
async def test_entities_table_columns_and_unique_constraint(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        cols = await conn.run_sync(
            lambda sync_conn: {c["name"]: c for c in inspect(sync_conn).get_columns("entities")}
        )
        uniques = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_unique_constraints("entities")
        )

    assert {
        "entity_id",
        "tenant_id",
        "entity_type",
        "external_id",
        "properties",
        "created_at",
    } <= set(cols)
    unique_cols = {tuple(sorted(u["column_names"])) for u in uniques}
    assert ("entity_type", "external_id", "tenant_id") in unique_cols


@pytest.mark.asyncio
async def test_relationships_fk_to_entities_with_on_delete_cascade(engine: AsyncEngine) -> None:
    """Both endpoints FK to entities.entity_id with ON DELETE CASCADE.

    This is the load-bearing invariant for the semantic graph: deleting
    an entity must drop its edges so dangling relationships can't accrue.
    """
    async with engine.connect() as conn:
        fks = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_foreign_keys("relationships")
        )

    by_column = {tuple(fk["constrained_columns"]): fk for fk in fks}
    assert ("src_entity_id",) in by_column
    assert ("dst_entity_id",) in by_column
    for fk in fks:
        assert fk["referred_table"] == "entities"
        assert fk["referred_columns"] == ["entity_id"]
        # SQLAlchemy reports options under "options"; in aiosqlite the key
        # is "ondelete" — accept either dialect spelling.
        options = fk.get("options", {}) or {}
        ondelete = options.get("ondelete") or fk.get("ondelete")
        assert (ondelete or "").upper() == "CASCADE", f"missing ON DELETE CASCADE: {fk}"


@pytest.mark.asyncio
async def test_dialect_portable_indexes_exist(engine: AsyncEngine) -> None:
    """The indexes declared on the Model (not the Postgres-only ones) materialize."""
    expected: dict[str, set[str]] = {
        "episodes": {"ix_episodes_tenant_emitted", "ix_episodes_correlation"},
        "playbooks": {"ix_playbooks_tenant_path"},
        "entities": {"ix_entities_tenant_type"},
        "relationships": {
            "ix_relationships_src_type",
            "ix_relationships_dst_type",
            "ix_relationships_tenant",
        },
    }
    async with engine.connect() as conn:
        for table, names in expected.items():
            got = await conn.run_sync(
                lambda sync_conn, t=table: {i["name"] for i in inspect(sync_conn).get_indexes(t)}
            )
            missing = names - got
            assert not missing, f"{table} missing indexes: {missing}"


# ---------------------------- real CRUD round-trips ----------------------


@pytest.mark.asyncio
async def test_episode_insert_and_query_round_trip(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as session:
        episode = EpisodeModel(
            tenant_id=TENANT_A,
            correlation_id="corr-001",
            agent_id="runtime_threat",
            action="invocation_completed",
            payload={"finding_count": 3, "by_severity": {"critical": 1}},
            embedding=[0.1] * EMBEDDING_DIM,
        )
        session.add(episode)
        await session.commit()
        await session.refresh(episode)

    async with session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(EpisodeModel).where(EpisodeModel.correlation_id == "corr-001")
                )
            )
            .scalars()
            .all()
        )

    assert len(rows) == 1
    assert rows[0].tenant_id == TENANT_A
    assert rows[0].payload == {"finding_count": 3, "by_severity": {"critical": 1}}
    assert rows[0].embedding is not None and len(rows[0].embedding) == EMBEDDING_DIM
    assert isinstance(rows[0].emitted_at, datetime)
    # The model's default `_utcnow()` returns a tz-aware datetime. SQLite
    # strips the tz on read (it has no native TIMESTAMPTZ); Postgres
    # preserves it. The Postgres-integration test (Task 10) asserts
    # tz-awareness end-to-end.


@pytest.mark.asyncio
async def test_playbook_unique_constraint_blocks_duplicate_version(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    from sqlalchemy.exc import IntegrityError

    async with session_factory() as session:
        session.add(
            PlaybookModel(
                tenant_id=TENANT_A,
                path="remediation.s3.public_bucket",
                version=1,
                active=True,
                body={"steps": ["block-public-access", "alert-owner"]},
            )
        )
        await session.commit()

    async with session_factory() as session:
        session.add(
            PlaybookModel(
                tenant_id=TENANT_A,
                path="remediation.s3.public_bucket",
                version=1,  # duplicate (tenant_id, path, version)
                active=True,
                body={"steps": ["force-error"]},
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


@pytest.mark.asyncio
async def test_entity_unique_constraint_blocks_duplicate_external_id(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    from sqlalchemy.exc import IntegrityError

    async with session_factory() as session:
        session.add(
            EntityModel(
                entity_id="01ENTITY00000000000000000A",
                tenant_id=TENANT_A,
                entity_type="host",
                external_id="i-0123456789abcdef0",
                properties={"image": "nginx:1.27"},
            )
        )
        await session.commit()

    async with session_factory() as session:
        session.add(
            EntityModel(
                entity_id="01ENTITY00000000000000000B",
                tenant_id=TENANT_A,
                entity_type="host",
                external_id="i-0123456789abcdef0",  # duplicate
                properties={},
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()


@pytest.mark.asyncio
async def test_entity_same_external_id_allowed_across_tenants(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Tenant isolation extends to the natural-key uniqueness: tenant A's
    `i-0123456789abcdef0` and tenant B's `i-0123456789abcdef0` are
    distinct entities."""
    async with session_factory() as session:
        session.add(
            EntityModel(
                entity_id="01ENTITY00000000000000000A",
                tenant_id=TENANT_A,
                entity_type="host",
                external_id="i-0123456789abcdef0",
            )
        )
        session.add(
            EntityModel(
                entity_id="01ENTITY00000000000000000B",
                tenant_id=TENANT_B,
                entity_type="host",
                external_id="i-0123456789abcdef0",
            )
        )
        await session.commit()  # no IntegrityError


@pytest.mark.asyncio
async def test_relationship_insert_and_cascade_delete(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Insert two entities + one relationship; delete src → relationship gone."""
    async with session_factory() as session:
        src = EntityModel(
            entity_id="01ENTITYSRC00000000000000A",
            tenant_id=TENANT_A,
            entity_type="host",
            external_id="i-source",
        )
        dst = EntityModel(
            entity_id="01ENTITYDST00000000000000A",
            tenant_id=TENANT_A,
            entity_type="finding",
            external_id="RUNTIME-PROCESS-X-001-y",
        )
        session.add_all([src, dst])
        await session.flush()

        edge = RelationshipModel(
            tenant_id=TENANT_A,
            src_entity_id=src.entity_id,
            dst_entity_id=dst.entity_id,
            relationship_type="EMITTED",
            properties={"detected_at": "2026-05-11T12:00:00Z"},
        )
        session.add(edge)
        await session.commit()
        edge_id = edge.relationship_id

    # Delete the src entity — the FK with ON DELETE CASCADE must remove the edge.
    async with session_factory() as session:
        # SQLite requires PRAGMA foreign_keys=ON; aiosqlite enables it via dialect.
        await session.execute(__import__("sqlalchemy").text("PRAGMA foreign_keys=ON"))
        src = await session.get(EntityModel, "01ENTITYSRC00000000000000A")
        assert src is not None
        await session.delete(src)
        await session.commit()

    async with session_factory() as session:
        edge_row = await session.get(RelationshipModel, edge_id)
        assert edge_row is None, "ON DELETE CASCADE should have removed the relationship"


@pytest.mark.asyncio
async def test_tenant_id_is_a_required_leading_column_on_every_table(
    engine: AsyncEngine,
) -> None:
    """Every table carries tenant_id as a non-nullable column.

    Load-bearing for Task 7 RLS: a row without `tenant_id` can't be
    filtered by `current_setting('app.tenant_id')`.
    """
    async with engine.connect() as conn:
        for table in ("episodes", "playbooks", "entities", "relationships"):
            cols = await conn.run_sync(
                lambda sync_conn, t=table: {c["name"]: c for c in inspect(sync_conn).get_columns(t)}
            )
            assert "tenant_id" in cols, f"{table} missing tenant_id"
            assert not cols["tenant_id"]["nullable"], f"{table}.tenant_id must be NOT NULL"
