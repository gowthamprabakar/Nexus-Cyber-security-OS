"""Tests for the identity knowledge-graph writer (v0.4 Stage 1.2/D.2).

End-to-end through ``agent.run()`` against a real in-memory ``SemanticStore``: the
typed ``IdentityListing`` lands as IDENTITY (users/roles/groups) + POLICY nodes with
ATTACHED_TO / MEMBER_OF edges. ``HAS_ACCESS_TO`` is Stage 3 (cross-agent) — not written
here. Opt-in: default (no store) writes nothing. The listing fetch is patched at module
level (the typed source, not OCSF dicts), matching the unit-test rig.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from identity import agent as agent_mod
from identity.agent import run
from identity.tools.aws_iam import IamGroup, IamRole, IamUser, IdentityListing
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio

_TENANT = "cust_test"
_NOW = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
_ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


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


def _user(
    arn: str, name: str, *, attached: tuple[str, ...] = (), groups: tuple[str, ...] = ()
) -> IamUser:
    return IamUser(
        arn=arn,
        name=name,
        user_id=f"AIDA-{name.upper()}",
        create_date=_NOW,
        last_used_at=_NOW,
        attached_policy_arns=attached,
        group_memberships=groups,
    )


def _group(arn: str, name: str, *, attached: tuple[str, ...] = ()) -> IamGroup:
    return IamGroup(
        arn=arn,
        name=name,
        group_id=f"AGPA-{name.upper()}",
        create_date=_NOW,
        attached_policy_arns=attached,
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


async def test_run_with_store_writes_principals_and_edges(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # bob is a member of admins (group carries the AdministratorAccess attachment).
    listing = IdentityListing(
        users=(_user("arn:aws:iam::111122223333:user/bob", "bob", groups=("admins",)),),
        roles=(),
        groups=(_group("arn:aws:iam::111122223333:group/admins", "admins", attached=(_ADMIN,)),),
    )
    _patch_listing(monkeypatch, listing)

    await run(_contract(tmp_path), semantic_store=store)

    identities = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="identity")
    by_id = {e.external_id: e for e in identities}
    assert set(by_id) == {
        "arn:aws:iam::111122223333:user/bob",
        "arn:aws:iam::111122223333:group/admins",
    }
    assert by_id["arn:aws:iam::111122223333:user/bob"].properties["principal_type"] == "user"

    policies = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="policy")
    assert {p.external_id for p in policies} == {_ADMIN}

    # MEMBER_OF: bob → admins is traversable.
    bob = by_id["arn:aws:iam::111122223333:user/bob"]
    neighbors = await store.neighbors(tenant_id=_TENANT, entity_id=bob.entity_id, depth=1)
    assert any(n.external_id == "arn:aws:iam::111122223333:group/admins" for n in neighbors)

    # ATTACHED_TO: AdministratorAccess → admins group is traversable from the policy node.
    admin_policy = policies[0]
    pol_neighbors = await store.neighbors(
        tenant_id=_TENANT, entity_id=admin_policy.entity_id, depth=1
    )
    assert any(n.external_id == "arn:aws:iam::111122223333:group/admins" for n in pol_neighbors)


async def test_managed_policy_node_deduped_across_principals(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Two roles attach the same managed policy → one POLICY node (upsert dedup).
    listing = IdentityListing(
        users=(),
        roles=(
            IamRole(
                arn="arn:aws:iam::111122223333:role/r1",
                name="r1",
                role_id="AROA-R1",
                create_date=_NOW,
                last_used_at=_NOW,
                assume_role_policy_document={},
                attached_policy_arns=(_ADMIN,),
            ),
            IamRole(
                arn="arn:aws:iam::111122223333:role/r2",
                name="r2",
                role_id="AROA-R2",
                create_date=_NOW,
                last_used_at=_NOW,
                assume_role_policy_document={},
                attached_policy_arns=(_ADMIN,),
            ),
        ),
        groups=(),
    )
    _patch_listing(monkeypatch, listing)

    await run(_contract(tmp_path), semantic_store=store)

    policies = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="policy")
    assert len(policies) == 1


async def test_run_without_store_writes_nothing(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    listing = IdentityListing(
        users=(_user("arn:aws:iam::111122223333:user/bob", "bob"),), roles=(), groups=()
    )
    _patch_listing(monkeypatch, listing)
    await run(_contract(tmp_path))
    assert await store.list_entities_by_type(tenant_id=_TENANT, entity_type="identity") == []
