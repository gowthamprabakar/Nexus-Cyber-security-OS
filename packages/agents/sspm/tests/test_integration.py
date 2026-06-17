"""SSPM integration tests (D.10 PR6).

Two end-to-end shapes:
1. All three connectors fire in one run → merged OCSF 2003 findings + a coherent SaaS
   subgraph (SAAS_TENANT + OAUTH_APP + AUTHORIZED) on a real in-memory SemanticStore.
2. Two tenants scanned separately → each run's graph is tenant-scoped (no cross-tenant
   leakage in the SemanticStore).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sspm.agent import run
from sspm.tools.github_org import GITHUB_API
from sspm.tools.slack import SLACK_API

pytestmark = pytest.mark.asyncio

_PERMITTED = ["read_github_org", "read_m365_tenant", "read_slack_workspace"]


def _contract(tmp_path: Path, *, customer_id: str = "cust_test") -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="sspm",
        customer_id=customer_id,
        task="SaaS posture scan",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=1, tokens=1, wall_clock_sec=60.0, cloud_api_calls=200, mb_written=10
        ),
        permitted_tools=_PERMITTED,
        completion_condition="findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


class _FakeHttp:
    def __init__(self, routes: dict[str, tuple[int, dict[str, str], Any]]) -> None:
        self.routes = routes

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], Any]:
        return self.routes.get(url, (404, {}, {"ok": False}))


class _FakeGraph:
    def __init__(self, collections: dict[str, list], objects: dict[str, dict]) -> None:
        self._c = collections
        self._o = objects

    async def get_all(self, resource: str, *, select: str | None = None) -> list[dict[str, Any]]:
        return self._c.get(resource, [])

    async def get_one(self, resource: str) -> dict[str, Any]:
        return self._o.get(resource, {})


def _github() -> _FakeHttp:
    return _FakeHttp(
        {
            f"{GITHUB_API}/orgs/acme": (200, {}, {"two_factor_requirement_enabled": False}),
            f"{GITHUB_API}/orgs/acme/repos?per_page=100": (200, {}, []),
        }
    )


def _m365() -> _FakeGraph:
    return _FakeGraph(
        collections={
            "identity/conditionalAccessPolicies": [],
            "oauth2PermissionGrants": [{"clientId": "app-1", "scope": "Mail.Read"}],
        },
        objects={"policies/identitySecurityDefaultsEnforcementPolicy": {"isEnabled": True}},
    )


def _slack() -> _FakeHttp:
    return _FakeHttp(
        {
            f"{SLACK_API}/team.info": (
                200,
                {},
                {"ok": True, "team": {"id": "T01", "name": "Acme"}},
            ),
            f"{SLACK_API}/users.list?limit=200": (
                200,
                {},
                {
                    "ok": True,
                    "members": [{"id": "U1", "is_restricted": True}],
                    "response_metadata": {},
                },
            ),
            f"{SLACK_API}/admin.apps.approved.list?limit=100": (200, {}, {"ok": False}),
        }
    )


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


async def test_all_connectors_one_run(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEXUS_SSPM_GITHUB_TOKEN", "ghp")
    monkeypatch.setenv("NEXUS_SSPM_SLACK_TOKEN", "xoxb")
    report = await run(
        _contract(tmp_path),
        github_org="acme",
        github_transport=_github(),
        m365_tenant="contoso",
        m365_graph=_m365(),
        slack_workspace=True,
        slack_transport=_slack(),
        semantic_store=store,
    )
    # Findings from all three connectors merge into one OCSF 2003 report.
    assert report.total >= 3
    doc = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert all(f["class_uid"] == 2003 for f in doc["findings"])

    # Coherent SaaS subgraph: three tenants + the M365 OAuth app, AUTHORIZED-linked.
    tenants = await store.list_entities_by_type(tenant_id="cust_test", entity_type="saas_tenant")
    assert {t.external_id for t in tenants} == {"github:acme", "m365:contoso", "slack:T01"}
    apps = await store.list_entities_by_type(tenant_id="cust_test", entity_type="oauth_app")
    assert "m365:contoso:app:app-1" in {a.external_id for a in apps}


async def test_two_tenants_are_isolated_in_the_graph(
    tmp_path: Path, store: SemanticStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEXUS_SSPM_GITHUB_TOKEN", "ghp")
    await run(
        _contract(tmp_path / "a", customer_id="cust_a"),
        github_org="acme",
        github_transport=_github(),
        semantic_store=store,
    )
    await run(
        _contract(tmp_path / "b", customer_id="cust_b"),
        github_org="acme",
        github_transport=_github(),
        semantic_store=store,
    )
    a = await store.list_entities_by_type(tenant_id="cust_a", entity_type="saas_tenant")
    b = await store.list_entities_by_type(tenant_id="cust_b", entity_type="saas_tenant")
    assert [t.external_id for t in a] == ["github:acme"]
    assert [t.external_id for t in b] == ["github:acme"]
    # Same external_id, different tenant partitions → distinct entity rows (no leak).
    assert a[0].entity_id != b[0].entity_id
