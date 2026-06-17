"""Tests for the SSPM knowledge-graph writer (D.10 PR5 — SaaS spine).

Direct ``record_*`` against a real in-memory ``SemanticStore``: connector inventories land
as SAAS_TENANT + OAUTH_APP nodes with AUTHORIZED edges (the ADR-018 SaaS vocab, first
consumer). The run()-level opt-in wiring is covered in test_agent_unit.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sspm.kg_writer import KnowledgeGraphWriter
from sspm.tools.github_org import GitHubOrgInventory
from sspm.tools.m365 import M365Inventory, M365OAuthGrant
from sspm.tools.slack import SlackOAuthApp, SlackWorkspaceInventory

pytestmark = pytest.mark.asyncio

_TENANT = "cust_test"


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


async def test_records_tenants_apps_and_authorized_edges(store: SemanticStore) -> None:
    kg = KnowledgeGraphWriter(store, _TENANT)
    await kg.record_github(
        GitHubOrgInventory(
            org="acme",
            two_factor_required=True,
            default_repository_permission="read",
            members_can_create_public_repos=False,
        )
    )
    await kg.record_m365(
        M365Inventory(
            tenant_id="contoso",
            security_defaults_enabled=True,
            allow_invites_from="none",
            user_consent_allowed=False,
            conditional_access_policy_count=1,
            global_admin_count=2,
            oauth_grants=(M365OAuthGrant(client_id="app-1", scopes=("Mail.Read",)),),
        )
    )
    await kg.record_slack(
        SlackWorkspaceInventory(
            team_id="T01",
            team_name="Acme Slack",
            owners=1,
            admins=1,
            guests=0,
            members_without_2fa=0,
            oauth_apps=(SlackOAuthApp(app_id="A1", name="Bot", scopes=("admin",)),),
        )
    )

    tenants = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="saas_tenant")
    assert {t.external_id for t in tenants} == {
        "github:acme",
        "m365:contoso",
        "slack:T01",
    }

    apps = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="oauth_app")
    assert {a.external_id for a in apps} == {
        "m365:contoso:app:app-1",
        "slack:T01:app:A1",
    }

    # AUTHORIZED: the M365 app reaches its tenant.
    m365_app = next(a for a in apps if a.external_id == "m365:contoso:app:app-1")
    neighbors = await store.neighbors(tenant_id=_TENANT, entity_id=m365_app.entity_id, depth=1)
    assert any(n.external_id == "m365:contoso" for n in neighbors)


async def test_inert_when_no_store() -> None:
    # Base-class contract: a writer with no store is a no-op (no crash, .enabled False).
    kg = KnowledgeGraphWriter(None, _TENANT)
    assert kg.enabled is False
    await kg.record_github(
        GitHubOrgInventory(
            org="acme",
            two_factor_required=True,
            default_repository_permission="read",
            members_can_create_public_repos=False,
        )
    )  # must not raise
