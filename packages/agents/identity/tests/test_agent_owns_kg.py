"""Test that identity agent.run() writes OWNS/OWNED_BY edges for IAM user access keys.

Task 6 of the operating-path wiring cycle: verify that _credential_grants is called and
record_credential_ownership is invoked inside the `if semantic_store is not None:` block.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.graph_types import EdgeType, NodeCategory
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from identity import agent as agent_mod
from identity.agent import run
from identity.tools.aws_iam import IamUser, IdentityListing
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio

_TENANT = "cust_test"
_NOW = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
_USER_ARN = "arn:aws:iam::111122223333:user/alice"
_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="identity",
        customer_id=_TENANT,
        task="Identity scan",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=5, tokens=10_000, wall_clock_sec=60.0, cloud_api_calls=500, mb_written=10
        ),
        permitted_tools=["aws_iam_list_identities"],
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _patch_listing(monkeypatch: pytest.MonkeyPatch, listing: IdentityListing) -> None:
    async def fake_list(**_: Any) -> IdentityListing:
        return listing

    monkeypatch.setattr(agent_mod, "aws_iam_list_identities", fake_list)


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


async def test_run_writes_owns_edge_for_user_access_key(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run() with a user that has access_key_ids must write IDENTITY --OWNS--> SECRET."""
    listing = IdentityListing(
        users=(
            IamUser(
                arn=_USER_ARN,
                name="alice",
                user_id="AIDA-ALICE",
                create_date=_NOW,
                last_used_at=_NOW,
                attached_policy_arns=(),
                group_memberships=(),
                access_key_ids=(_KEY_ID,),
            ),
        ),
        roles=(),
        groups=(),
    )
    _patch_listing(monkeypatch, listing)

    await run(_contract(tmp_path), semantic_store=store)

    # The user identity node must exist.
    user_id = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.IDENTITY.value,
        external_id=_USER_ARN,
        properties={},
    )

    # OWNS edge: IDENTITY --OWNS--> SECRET(key_id)
    owns_edges = await store.get_relationships_from(
        tenant_id=_TENANT,
        src_entity_id=user_id,
        edge_types=(EdgeType.OWNS.value,),
    )
    assert len(owns_edges) == 1, "expected exactly one OWNS edge from user to access key"

    # The destination should be the SECRET node keyed by the access key ID.
    cred_id = await store.upsert_entity(
        tenant_id=_TENANT,
        entity_type=NodeCategory.SECRET.value,
        external_id=_KEY_ID,
        properties={},
    )
    assert owns_edges[0].dst_entity_id == cred_id, "OWNS edge destination must be the SECRET node"

    # OWNED_BY reverse edge: SECRET --OWNED_BY--> IDENTITY
    owned_by_edges = await store.get_relationships_from(
        tenant_id=_TENANT,
        src_entity_id=cred_id,
        edge_types=(EdgeType.OWNED_BY.value,),
    )
    assert len(owned_by_edges) == 1, "expected exactly one OWNED_BY edge from key to user"
    assert owned_by_edges[0].dst_entity_id == user_id, "OWNED_BY edge must point back to user"


async def test_run_without_store_writes_no_credential_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no semantic_store, run() must not raise and produces no graph writes."""
    listing = IdentityListing(
        users=(
            IamUser(
                arn=_USER_ARN,
                name="alice",
                user_id="AIDA-ALICE",
                create_date=_NOW,
                last_used_at=_NOW,
                attached_policy_arns=(),
                group_memberships=(),
                access_key_ids=(_KEY_ID,),
            ),
        ),
        roles=(),
        groups=(),
    )
    _patch_listing(monkeypatch, listing)
    # Must not raise even without a store.
    report = await run(_contract(tmp_path), semantic_store=None)
    assert report is not None
