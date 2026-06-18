"""Live integration tests for `charter.memory` against a real Postgres + pgvector.

Skipped by default. Enable with:

    docker compose -f docker/docker-compose.dev.yml up -d postgres
    NEXUS_LIVE_POSTGRES=1 uv run pytest \\
        packages/charter/tests/integration/test_memory_live_postgres.py -v

Prerequisites:
- Postgres 16 + pgvector available at `localhost:5432`. The dev compose
  bundles `pgvector/pgvector:pg16` so `docker compose up -d postgres`
  is the one-line setup.
- The `nexus` database (default from the compose file) exists with the
  `nexus / nexus_dev` credentials. Override the full DSN with
  `NEXUS_LIVE_POSTGRES_URL` if you're targeting a different cluster.

These tests cover the contract that aiosqlite can't exercise:

- Alembic `upgrade head` succeeds against a real Postgres (both
  migrations: `0001_memory_baseline` + `0002_memory_rls`).
- Both Postgres extensions (`vector`, `ltree`) install cleanly.
- CRUD round-trip on each of the four memory tables under the
  Postgres-native column types (JSONB, VECTOR, LTREE).
- pgvector cosine-distance ANN returns the right top-K ranking against
  100 inserted episodes.
- Row-Level Security: a session bound to tenant A cannot read
  tenant B's rows. The Task-7 RLS policies fire correctly when
  `MemoryService.session(tenant_id=...)` issues `SET LOCAL`.

Each test installs the schema fresh into a dedicated test database so
re-runs are deterministic and don't interfere with the host's
`nexus_control_plane` migrations.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from charter.audit import AuditLog
from charter.memory.embedding import FakeEmbeddingProvider
from charter.memory.service import MemoryService
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

pytestmark = pytest.mark.integration


def _live_enabled() -> bool:
    return os.environ.get("NEXUS_LIVE_POSTGRES") == "1"


_DEFAULT_ADMIN_URL = "postgresql+asyncpg://nexus:nexus_dev@localhost:5432/postgres"
_DEFAULT_TARGET_URL = "postgresql+asyncpg://nexus:nexus_dev@localhost:5432/nexus_memory_test"

_TARGET_URL = os.environ.get("NEXUS_LIVE_POSTGRES_URL", _DEFAULT_TARGET_URL)
_ADMIN_URL = os.environ.get("NEXUS_LIVE_POSTGRES_ADMIN_URL", _DEFAULT_ADMIN_URL)


def _alembic_url_from(async_url: str) -> str:
    """Alembic ships a sync env; swap asyncpg → psycopg2 in the DSN."""
    return async_url.replace("+asyncpg", "+psycopg2")


def _skip_reason() -> str:
    return (
        f"set NEXUS_LIVE_POSTGRES=1 and bring infra up via "
        f"`docker compose -f docker/docker-compose.dev.yml up -d postgres`; "
        f"current target URL: {_TARGET_URL}"
    )


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _live_enabled(), reason=_skip_reason()),
]


# ---------------------------- fixtures ----------------------------------


@pytest_asyncio.fixture
async def fresh_database() -> AsyncIterator[str]:
    """Drop + recreate the test database for a clean slate per test.

    Connecting as admin to the default `postgres` DB so we can issue
    `DROP DATABASE / CREATE DATABASE` against the target.
    """
    target_db = _TARGET_URL.rsplit("/", 1)[-1]
    admin_engine = create_async_engine(_ADMIN_URL, isolation_level="AUTOCOMMIT")
    try:
        async with admin_engine.connect() as conn:
            await conn.execute(text(f"DROP DATABASE IF EXISTS {target_db}"))
            await conn.execute(text(f"CREATE DATABASE {target_db}"))
    finally:
        await admin_engine.dispose()

    yield _TARGET_URL


def _run_migrations(async_url: str) -> None:
    """Drive alembic `upgrade head` against the given DB."""
    from pathlib import Path

    charter_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(charter_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(charter_root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", _alembic_url_from(async_url))
    command.upgrade(cfg, "head")


@pytest_asyncio.fixture
async def engine(fresh_database: str) -> AsyncIterator[AsyncEngine]:
    _run_migrations(fresh_database)
    eng = create_async_engine(fresh_database)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def audit_log(tmp_path):  # type: ignore[no-untyped-def]
    return AuditLog(
        path=tmp_path / "audit.jsonl",
        agent="memory_live_integration",
        run_id="01HV0T0000000000000000RUN1",
    )


@pytest_asyncio.fixture
async def service(
    session_factory: async_sessionmaker[AsyncSession],
    audit_log: AuditLog,
) -> MemoryService:
    return MemoryService(
        session_factory=session_factory,
        embedder=FakeEmbeddingProvider(),
        audit_log=audit_log,
    )


_TENANT_A = "01HV0T0000000000000000TENA"
_TENANT_B = "01HV0T0000000000000000TENB"


# ---------------------------- alembic upgrade head -----------------------


@pytest.mark.asyncio
async def test_alembic_upgrade_head_creates_all_tables_and_extensions(
    engine: AsyncEngine,
) -> None:
    async with engine.connect() as conn:
        # pgvector + ltree must be installed by 0001_memory_baseline.
        ext_rows = (
            (await conn.execute(text("SELECT extname FROM pg_extension ORDER BY extname")))
            .scalars()
            .all()
        )
        assert "vector" in ext_rows
        assert "ltree" in ext_rows

        # The four memory tables exist.
        tables = (
            (
                await conn.execute(
                    text(
                        "SELECT tablename FROM pg_tables "
                        "WHERE schemaname = 'public' ORDER BY tablename"
                    )
                )
            )
            .scalars()
            .all()
        )
        for table in ("episodes", "playbooks", "entities", "relationships"):
            assert table in tables

        # The distinct alembic version table exists (not the default name).
        assert "alembic_version_memory" in tables
        assert "alembic_version" not in tables


# ---------------------------- CRUD round-trip ---------------------------


@pytest.mark.asyncio
async def test_crud_round_trip_on_all_four_tables(service: MemoryService) -> None:
    async with service.session(tenant_id=_TENANT_A):
        # Episodic
        episode_id = await service.append_event(
            tenant_id=_TENANT_A,
            correlation_id="corr-1",
            agent_id="cloud_posture",
            action="finding.created",
            payload={"text": "s3 bucket public", "severity": "high"},
        )
        # Procedural
        version = await service.procedural.publish_version(
            tenant_id=_TENANT_A,
            path="remediation.s3.public_bucket",
            body={"steps": ["disable-acl"]},
        )
        # Semantic
        host_id = await service.semantic.upsert_entity(
            tenant_id=_TENANT_A,
            entity_type="host",
            external_id="i-abc",
            properties={"region": "us-east-1"},
        )
        finding_id = await service.semantic.upsert_entity(
            tenant_id=_TENANT_A,
            entity_type="finding",
            external_id="F-1",
        )
        rid = await service.semantic.add_relationship(
            tenant_id=_TENANT_A,
            src_entity_id=host_id,
            dst_entity_id=finding_id,
            relationship_type="HAS_FINDING",
        )

    assert episode_id > 0
    assert version == 1
    assert len(host_id) == 26
    assert rid > 0

    # Read paths.
    async with service.session(tenant_id=_TENANT_A):
        episodes = await service.episodic.query_recent(tenant_id=_TENANT_A, limit=10)
        assert len(episodes) == 1

        active = await service.procedural.get_active(
            tenant_id=_TENANT_A,
            path="remediation.s3.public_bucket",
        )
        assert active is not None and active.version == 1

        neighbors = await service.semantic.neighbors(
            tenant_id=_TENANT_A, entity_id=host_id, depth=1
        )
        assert {n.external_id for n in neighbors} == {"F-1"}


@pytest.mark.asyncio
async def test_add_relationship_cross_run_dedup_on_real_postgres(
    service: MemoryService,
) -> None:
    """ADR-022 on real Postgres — the `pg_insert(...).on_conflict_do_nothing` path
    (distinct from sqlite) collapses a re-written edge to one row, first-wins."""
    async with service.session(tenant_id=_TENANT_A):
        host_id = await service.semantic.upsert_entity(
            tenant_id=_TENANT_A, entity_type="host", external_id="i-dedupe"
        )
        finding_id = await service.semantic.upsert_entity(
            tenant_id=_TENANT_A, entity_type="finding", external_id="F-dedupe"
        )
        first = await service.semantic.add_relationship(
            tenant_id=_TENANT_A,
            src_entity_id=host_id,
            dst_entity_id=finding_id,
            relationship_type="AFFECTS",
            properties={"severity": "high"},
        )
        # A second write of the same edge (different properties) is a dedup hit.
        second = await service.semantic.add_relationship(
            tenant_id=_TENANT_A,
            src_entity_id=host_id,
            dst_entity_id=finding_id,
            relationship_type="AFFECTS",
            properties={"severity": "low"},
        )
        assert second == first  # same relationship_id; no second row

    async with service.session(tenant_id=_TENANT_A):
        neighbors = await service.semantic.neighbors(
            tenant_id=_TENANT_A, entity_id=host_id, depth=1
        )
        assert [n.external_id for n in neighbors] == ["F-dedupe"]  # exactly one edge


@pytest.mark.asyncio
async def test_get_relationships_from_on_real_postgres(service: MemoryService) -> None:
    """ADR-022 edge accessor on real Postgres — outgoing edges, type filter, tenant scope."""
    async with service.session(tenant_id=_TENANT_A):
        host = await service.semantic.upsert_entity(
            tenant_id=_TENANT_A, entity_type="host", external_id="i-edges"
        )
        finding = await service.semantic.upsert_entity(
            tenant_id=_TENANT_A, entity_type="finding", external_id="F-edges"
        )
        cve = await service.semantic.upsert_entity(
            tenant_id=_TENANT_A, entity_type="cve", external_id="CVE-edges"
        )
        await service.semantic.add_relationship(
            tenant_id=_TENANT_A,
            src_entity_id=host,
            dst_entity_id=finding,
            relationship_type="AFFECTS",
        )
        await service.semantic.add_relationship(
            tenant_id=_TENANT_A,
            src_entity_id=host,
            dst_entity_id=cve,
            relationship_type="VULNERABLE_TO",
        )

    async with service.session(tenant_id=_TENANT_A):
        all_edges = await service.semantic.get_relationships_from(
            tenant_id=_TENANT_A, src_entity_id=host
        )
        assert {(e.dst_entity_id, e.relationship_type) for e in all_edges} == {
            (finding, "AFFECTS"),
            (cve, "VULNERABLE_TO"),
        }
        affects = await service.semantic.get_relationships_from(
            tenant_id=_TENANT_A, src_entity_id=host, edge_types=("AFFECTS",)
        )
        assert [e.dst_entity_id for e in affects] == [finding]

    # Off-tenant read returns nothing (RLS + explicit tenant filter).
    async with service.session(tenant_id=_TENANT_B):
        off = await service.semantic.get_relationships_from(tenant_id=_TENANT_B, src_entity_id=host)
        assert off == []


# ---------------------------- pgvector ANN ----------------------------


@pytest.mark.asyncio
async def test_pgvector_ann_returns_top_k_by_cosine_distance(
    service: MemoryService,
) -> None:
    """Insert 100 deterministic embeddings; search by the embedding of
    payload index 7 and expect index 7 to rank first.
    """
    embedder = FakeEmbeddingProvider()
    inserted_ids: list[int] = []

    async with service.session(tenant_id=_TENANT_A):
        for i in range(100):
            eid = await service.episodic.append_event(
                tenant_id=_TENANT_A,
                correlation_id=f"corr-{i}",
                agent_id="seed",
                action=f"event-{i}",
                payload={"text": f"payload-number-{i}"},
                embedding=embedder.embed(f"payload-number-{i}"),
            )
            inserted_ids.append(eid)

    target_embedding = embedder.embed("payload-number-7")

    async with service.session(tenant_id=_TENANT_A):
        results = await service.episodic.search_similar(
            tenant_id=_TENANT_A,
            embedding=target_embedding,
            top_k=5,
        )

    assert len(results) == 5
    # The exact match must rank #1.
    assert results[0].action == "event-7"


# ---------------------------- Row-Level Security ------------------------


@pytest.mark.asyncio
async def test_rls_isolates_tenants_on_episodes(service: MemoryService) -> None:
    """Tenant A's writes are invisible to a tenant-B session, even though
    the application-side filter would have caught it too — RLS is the
    primary defence and must hold on its own.
    """
    async with service.session(tenant_id=_TENANT_A):
        await service.episodic.append_event(
            tenant_id=_TENANT_A,
            correlation_id="c",
            agent_id="a",
            action="A-only",
            payload={"text": "a"},
        )

    # Direct SQL under tenant B's session — bypass application-side filter
    # to prove RLS itself, not the WHERE clause, is excluding the row.
    async with service.session(tenant_id=_TENANT_B) as session:
        rows = (await session.execute(text("SELECT episode_id FROM episodes"))).scalars().all()
        assert rows == []

    async with service.session(tenant_id=_TENANT_A) as session:
        rows = (await session.execute(text("SELECT episode_id FROM episodes"))).scalars().all()
        assert len(rows) == 1


@pytest.mark.asyncio
async def test_rls_isolates_tenants_on_playbooks(service: MemoryService) -> None:
    async with service.session(tenant_id=_TENANT_A):
        await service.procedural.publish_version(tenant_id=_TENANT_A, path="a.b.c", body={})

    async with service.session(tenant_id=_TENANT_B) as session:
        rows = (await session.execute(text("SELECT playbook_id FROM playbooks"))).scalars().all()
        assert rows == []


@pytest.mark.asyncio
async def test_rls_isolates_tenants_on_entities(service: MemoryService) -> None:
    async with service.session(tenant_id=_TENANT_A):
        await service.semantic.upsert_entity(
            tenant_id=_TENANT_A, entity_type="host", external_id="x"
        )

    async with service.session(tenant_id=_TENANT_B) as session:
        rows = (await session.execute(text("SELECT entity_id FROM entities"))).scalars().all()
        assert rows == []
