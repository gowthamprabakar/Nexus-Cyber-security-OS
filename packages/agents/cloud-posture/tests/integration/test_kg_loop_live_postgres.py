"""Load-bearing live proof — the KG read/write loop closes via real Postgres.

Task 6 of the KG-loop-closure plan
(`docs/superpowers/plans/2026-05-18-kg-loop-closure-cloud-posture-to-semanticstore.md`).
**SAFETY-CRITICAL — verified-against-HEAD discipline applies.**

Asserts two invariants against a real Postgres cluster (not aiosqlite,
not mocks):

1. **The keystone loop closes by execution.** Cloud Posture runs against
   fixture findings → writes asset + finding entities + AFFECTS
   relationships to the live SemanticStore → D.7's
   `memory_neighbors_walk` (test-side import of the real production
   function) traverses outward from the finding entity → returns the
   exact asset entities Cloud Posture just wrote. This is the first
   time, in production-equivalent infrastructure, that what Cloud
   Posture writes Investigation can actually read. Prior to this PR
   the same read/write loop was asserted only by mocks (`test_kg_writer.py`
   for the writer side; `test_eval_runner.py` for the report side; D.7's
   own tests for the walker side).

2. **The within-run REPEATED-WRITE case lands exactly one AFFECTS edge.**
   `SemanticStore.add_relationship` is INSERT-only at the substrate
   layer; without the writer's agent-side dedup, two `upsert_finding`
   calls on the same `(finding_id, asset_external_id)` pair would
   produce two AFFECTS rows. Against real Postgres the dedup must
   collapse the second visit to a no-op, otherwise the substrate fills
   with duplicates per scan. This is the test the user named as
   load-bearing on Task 3's approval: "this proves the dedup works
   against a real store, not mocked only."

What is OUT of scope for this proof:

- **Cross-run** duplicate-AFFECTS-edge dedup. v0.1 dedup is per-writer-
  instance only; across-run duplicates accumulate. Consciously accepted
  as v0.1 debt per the Task 3 approval. Surfaced in the Task 8
  verification record as a tracked follow-up, alongside the Neo4j
  escape-hatch. Do not collapse "within-run" and "cross-run" assertions
  here.
- The Phase-2 Neo4j swap. ADR-009's escape hatch (depth ≥ 4 + > 1M
  edges/tenant) is reaffirmed by the amendment Task 1 wrote; the
  dormant `cloud_posture/tools/neo4j_kg.py` remains the labelled door.
  The plan does not trigger that swap.

Skip discipline (mirrors `packages/charter/tests/integration/
test_memory_live_postgres.py`):

- `NEXUS_LIVE_POSTGRES=1` unset → SKIP with the actionable reason
  (the postgres compose command).
- env var set but Postgres unreachable → fixtures raise, which pytest
  records as ERRORs against the named test IDs (not silent passes).

Enable:

    docker compose -f docker/docker-compose.dev.yml up -d postgres
    NEXUS_LIVE_POSTGRES=1 uv run pytest \\
        packages/agents/cloud-posture/tests/integration/test_kg_loop_live_postgres.py -v
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory import SemanticStore
from charter.memory.models import EntityModel, RelationshipModel
from cloud_posture import agent as agent_mod
from cloud_posture.tools import aws_iam, aws_s3, prowler
from cloud_posture.tools.kg_writer import KnowledgeGraphWriter
from investigation.tools.memory_walk import memory_neighbors_walk
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def _live_enabled() -> bool:
    return os.environ.get("NEXUS_LIVE_POSTGRES") == "1"


_DEFAULT_ADMIN_URL = "postgresql+asyncpg://nexus:nexus_dev@localhost:5432/postgres"
_DEFAULT_TARGET_URL = "postgresql+asyncpg://nexus:nexus_dev@localhost:5432/nexus_kg_loop_test"

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


# ---------------------------- fixtures --------------------------------------


@pytest_asyncio.fixture
async def fresh_database() -> AsyncIterator[str]:
    """Drop + recreate the KG-loop test database for a clean slate per test."""
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
    """Drive alembic `upgrade head` against the given DB.

    Reuses `packages/charter/alembic` — the same migration set the
    F.5 lane uses, so the `entities` + `relationships` schema we end
    up with is bit-for-bit identical to production's.
    """
    charter_root = Path(__file__).resolve().parents[5] / "charter"
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


@pytest_asyncio.fixture
async def live_store(session_factory: async_sessionmaker[AsyncSession]) -> SemanticStore:
    return SemanticStore(session_factory)


# ---------------------------- shared fixtures for the scan ------------------


_TENANT = "cust_live_kg_loop"

_S3_FINDING_ARN = "arn:aws:s3:::live-loop-bucket"
_S3_FINDING_RAW: dict[str, Any] = {
    "CheckID": "s3_bucket_public_access",
    "Severity": "high",
    "Status": "FAIL",
    "ResourceArn": _S3_FINDING_ARN,
    "ResourceType": "AwsS3Bucket",
    "Region": "us-east-1",
    "AccountId": "111122223333",
    "StatusExtended": "Bucket has public ACL grant",
}


def _patch_aws_tools_with_one_s3_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wire fixture data into the four async tool wrappers.

    No live AWS. The Prowler stub returns exactly ONE finding so the
    test asserts a single-finding loop end-to-end.
    """

    async def fake_prowler(**_kwargs: Any) -> prowler.ProwlerResult:
        return prowler.ProwlerResult(raw_findings=[dict(_S3_FINDING_RAW)])

    async def fake_users() -> list[str]:
        return []

    async def fake_admin() -> list[dict[str, Any]]:
        return []

    async def fake_s3_list(**_kwargs: Any) -> list[str]:
        return []

    monkeypatch.setattr(prowler, "run_prowler_aws", fake_prowler)
    monkeypatch.setattr(aws_iam, "list_users_without_mfa", fake_users)
    monkeypatch.setattr(aws_iam, "list_admin_policies", fake_admin)
    monkeypatch.setattr(aws_s3, "list_buckets", fake_s3_list)


def _build_kg_enabled_contract(tmp_path: Path) -> ExecutionContract:
    """Eval-runner-style contract with the kg_upsert_* tools whitelisted.

    The production eval-runner contract excludes the KG tools because
    eval has always run KG-off; here we explicitly include them so the
    in-agent ToolRegistry permits the writer's calls.
    """
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="cloud_posture",
        customer_id=_TENANT,
        task="KG-loop live proof — one S3 finding",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=500,
            mb_written=10,
        ),
        permitted_tools=[
            "prowler_scan",
            "aws_s3_list_buckets",
            "aws_s3_describe",
            "aws_iam_list_users_without_mfa",
            "aws_iam_list_admin_policies",
            "kg_upsert_asset",
            "kg_upsert_finding",
        ],
        completion_condition="findings.json exists",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


# ---------------------------- test 1: loop closes ---------------------------


@pytest.mark.asyncio
async def test_loop_closes_via_memory_neighbors_walk_against_real_postgres(
    tmp_path: Path,
    live_store: SemanticStore,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: Cloud Posture writes → SemanticStore → D.7 walker reads.

    Asserts the KG read/write loop closes by execution against a real
    Postgres cluster running the production alembic migrations. **This is
    the first time the loop closes outside a mocked test.**
    """
    contract = _build_kg_enabled_contract(tmp_path)

    _patch_aws_tools_with_one_s3_finding(monkeypatch)
    report = await agent_mod.run(contract=contract, semantic_store=live_store)

    assert report.total == 1, f"fixture should produce exactly 1 finding, got {report.total}"
    finding = report.findings[0]
    finding_external_id = finding["finding_info"]["uid"]

    # The SemanticStore public API has no get-by-external-id helper, so
    # look up the finding's entity_id directly via the production
    # `EntityModel` shape — only to seed the walker.
    async with session_factory() as session:
        stmt = select(EntityModel.entity_id).where(
            EntityModel.tenant_id == _TENANT,
            EntityModel.entity_type == "finding",
            EntityModel.external_id == finding_external_id,
        )
        finding_entity_id = (await session.execute(stmt)).scalar_one_or_none()
        assert finding_entity_id is not None, (
            "Cloud Posture must have written the finding entity to "
            "SemanticStore — read-back returned None"
        )

    # The keystone assertion: D.7's production walker, seeded with the
    # finding entity Cloud Posture just wrote, returns the affected
    # asset entities Cloud Posture just wrote alongside it.
    neighbors = await memory_neighbors_walk(
        semantic_store=live_store,
        tenant_id=_TENANT,
        entity_id=finding_entity_id,
        depth=1,
        edge_types=("AFFECTS",),
    )

    neighbor_external_ids = {n.external_id for n in neighbors}
    assert neighbor_external_ids == {_S3_FINDING_ARN}, (
        "D.7's memory_neighbors_walk should return exactly the asset arns "
        f"Cloud Posture wrote; got {neighbor_external_ids}"
    )

    # Sanity-check the entity types: AFFECTS edges from a finding point at assets.
    assert all(n.entity_type == "asset" for n in neighbors), (
        f"AFFECTS neighbors must be assets; got {[(n.entity_type, n.external_id) for n in neighbors]}"
    )


# ---------------------------- test 2: REPEATED-WRITE ------------------------


@pytest.mark.asyncio
async def test_repeated_write_within_one_writer_yields_exactly_one_affects_edge(
    live_store: SemanticStore,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """The within-run dedup must hold against real Postgres.

    `SemanticStore.add_relationship` is INSERT-only — without the
    `KnowledgeGraphWriter`'s per-finding dedup table, two calls to
    `upsert_finding(...)` with the same `(finding_id, asset_external_id)`
    pair would produce two AFFECTS rows. Mocked tests
    (`test_kg_writer.py::test_dedup_collapses_same_finding_same_arn_across_two_calls`)
    pin the agent-side behaviour; this test proves the resulting graph
    state on real Postgres has exactly one row.

    Out of scope: cross-WRITER-instance duplicates. v0.1 dedup is
    per-writer-instance only; the graph WILL accumulate duplicate AFFECTS
    rows across separate agent runs against the same SemanticStore. That
    is consciously accepted v0.1 debt (recorded in the Task 8 verification
    record).
    """
    writer = KnowledgeGraphWriter(semantic_store=live_store, customer_id=_TENANT)

    finding_id = "CSPM-AWS-S3-001-repeated"
    arn = "arn:aws:s3:::repeat-bucket"

    # First write — should land one Asset entity, one Finding entity,
    # and one AFFECTS edge.
    await writer.upsert_finding(
        finding_id=finding_id,
        rule_id="CSPM-AWS-S3-001",
        severity="high",
        affected_arns=[arn],
    )
    # Second write with identical inputs — the agent-side dedup table
    # should collapse the second visit to a no-op for the AFFECTS edge.
    await writer.upsert_finding(
        finding_id=finding_id,
        rule_id="CSPM-AWS-S3-001",
        severity="high",
        affected_arns=[arn],
    )

    # Verify the resulting graph state: exactly ONE AFFECTS edge in the
    # relationships table for (tenant_id, finding-as-src, asset-as-dst,
    # type=AFFECTS).
    async with session_factory() as session:
        finding_eid_stmt = select(EntityModel.entity_id).where(
            EntityModel.tenant_id == _TENANT,
            EntityModel.entity_type == "finding",
            EntityModel.external_id == finding_id,
        )
        finding_eid = (await session.execute(finding_eid_stmt)).scalar_one()

        asset_eid_stmt = select(EntityModel.entity_id).where(
            EntityModel.tenant_id == _TENANT,
            EntityModel.entity_type == "asset",
            EntityModel.external_id == arn,
        )
        asset_eid = (await session.execute(asset_eid_stmt)).scalar_one()

        affects_count_stmt = select(RelationshipModel).where(
            RelationshipModel.tenant_id == _TENANT,
            RelationshipModel.src_entity_id == finding_eid,
            RelationshipModel.dst_entity_id == asset_eid,
            RelationshipModel.relationship_type == "AFFECTS",
        )
        affects_rows = (await session.execute(affects_count_stmt)).scalars().all()

    assert len(affects_rows) == 1, (
        "The within-run REPEATED-WRITE case must produce exactly ONE "
        f"AFFECTS edge; found {len(affects_rows)}. If this is >1 the "
        "agent-side dedup is broken against the real INSERT-only substrate."
    )


# ---------------------------- test 3: contract-permissions sanity -----------


@pytest.mark.asyncio
async def test_skip_kg_path_does_not_touch_substrate(
    tmp_path: Path,
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`semantic_store=None` must leave the entities + relationships tables empty.

    Confirms the same contract that the eval-runner has used since
    pre-reroute still produces zero graph writes when KG is off. Pairs
    with the back-compat gate (Task 5) — that one proves observable-
    output parity; this one proves the substrate is left untouched.
    """
    # Build the contract WITHOUT the kg_upsert_* tools (eval-runner shape).
    contract_no_kg = ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="cloud_posture",
        customer_id=_TENANT,
        task="KG-loop live proof — KG-off sanity",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=500,
            mb_written=10,
        ),
        permitted_tools=[
            "prowler_scan",
            "aws_s3_list_buckets",
            "aws_s3_describe",
            "aws_iam_list_users_without_mfa",
            "aws_iam_list_admin_policies",
        ],
        completion_condition="findings.json exists",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )

    _patch_aws_tools_with_one_s3_finding(monkeypatch)
    report = await agent_mod.run(contract=contract_no_kg, semantic_store=None)

    assert report.total == 1  # the agent still produces findings

    async with session_factory() as session:
        ent_count = (
            await session.execute(select(EntityModel).where(EntityModel.tenant_id == _TENANT))
        ).all()
        rel_count = (
            await session.execute(
                select(RelationshipModel).where(RelationshipModel.tenant_id == _TENANT)
            )
        ).all()

    assert len(ent_count) == 0, (
        f"semantic_store=None must leave the entities table empty for this tenant; "
        f"found {len(ent_count)} rows"
    )
    assert len(rel_count) == 0, (
        f"semantic_store=None must leave the relationships table empty for this tenant; "
        f"found {len(rel_count)} rows"
    )
