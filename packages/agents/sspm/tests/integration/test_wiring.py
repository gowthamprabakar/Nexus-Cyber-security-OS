"""Fleet Test Level 1 — sspm (D.10 SaaS Posture) wiring smoke.

Tier A: writes the SaaS spine + emits OCSF 2003 findings → the full §2.3 wiring assertions.
Modeled on the cloud-posture reference harness (the posture-feed scan shape). SSPM's
finding-bearing path drives the three SaaS connectors (GitHub + M365 + Slack) through
deterministic HTTP/Graph fakes — the same fakes the agent's own integration suite uses
(swiss-bar #3, real wire shapes, no mock theater).

L1 is SMOKE, not capability — it proves the plumbing (run completes, kg_writer writes the
SaaS spine, OCSF valid, tenant isolated, audit chain clean, inert offline). Precision/recall
is L2.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from charter.memory.graph_types import NodeCategory
from fleet_testkit import (
    assert_audit_chain,
    assert_entity_written,
    assert_no_entities,
    assert_ocsf_valid,
    assert_two_tenant_disjoint,
    in_memory_semantic_store,
    wiring_contract,
)
from sspm.agent import run
from sspm.tools.github_org import GITHUB_API
from sspm.tools.slack import SLACK_API

_PERMITTED = ["read_github_org", "read_m365_tenant", "read_slack_workspace"]
_CATEGORIES = (NodeCategory.SAAS_TENANT, NodeCategory.OAUTH_APP)
_OCSF_CLASS = 2003  # Compliance Finding (sspm.schemas)


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


def _seed_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seed the per-call SaaS credential env vars (source identifiers; never persisted)."""
    monkeypatch.setenv("NEXUS_SSPM_GITHUB_TOKEN", "ghp")
    monkeypatch.setenv("NEXUS_SSPM_SLACK_TOKEN", "xoxb")


def _findings(workspace: Path) -> list[dict[str, Any]]:
    payload = json.loads((workspace / "findings.json").read_text())
    return list(payload["findings"])


@pytest.mark.asyncio
async def test_wiring_sspm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tier A full §2.3: run completes · OCSF 2003 valid · SAAS_TENANT + OAUTH_APP written ·
    audit chain hash-verifies · tenant isolation."""
    _seed_tokens(monkeypatch)
    async with in_memory_semantic_store() as store:
        # tenant A
        ws_a = tmp_path / "a"
        contract_a = wiring_contract(
            ws_a, target_agent="sspm", permitted_tools=_PERMITTED, customer_id="tenant_a"
        )
        report_a = await run(
            contract=contract_a,
            github_org="acme",
            github_transport=_github(),
            m365_tenant="contoso",
            m365_graph=_m365(),
            slack_workspace=True,
            slack_transport=_slack(),
            semantic_store=store,
        )

        # run-completes + produced findings
        assert report_a.total >= 1
        findings = _findings(ws_a / "ws")
        assert findings, "no findings emitted"

        # OCSF valid (every emitted finding)
        for finding in findings:
            assert_ocsf_valid(finding, class_uid=_OCSF_CLASS)

        # kg_writer wrote the expected SaaS spine node types
        await assert_entity_written(store, tenant_id="tenant_a", category=NodeCategory.SAAS_TENANT)
        await assert_entity_written(store, tenant_id="tenant_a", category=NodeCategory.OAUTH_APP)

        # audit chain hash-verifies
        assert_audit_chain(ws_a / "ws" / "audit.jsonl")

        # tenant isolation: same input under tenant_b → disjoint subgraph
        ws_b = tmp_path / "b"
        contract_b = wiring_contract(
            ws_b,
            target_agent="sspm",
            permitted_tools=_PERMITTED,
            customer_id="tenant_b",
            delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0",
        )
        await run(
            contract=contract_b,
            github_org="acme",
            github_transport=_github(),
            m365_tenant="contoso",
            m365_graph=_m365(),
            slack_workspace=True,
            slack_transport=_slack(),
            semantic_store=store,
        )
        await assert_two_tenant_disjoint(
            store, tenant_a="tenant_a", tenant_b="tenant_b", categories=_CATEGORIES
        )


@pytest.mark.asyncio
async def test_wiring_sspm_inert_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No semantic_store → no graph writes; findings still emit (byte-identical offline)."""
    _seed_tokens(monkeypatch)
    async with in_memory_semantic_store() as store:
        contract = wiring_contract(
            tmp_path,
            target_agent="sspm",
            permitted_tools=_PERMITTED,
            customer_id="t_off",
        )
        report = await run(
            contract=contract,
            github_org="acme",
            github_transport=_github(),
            m365_tenant="contoso",
            m365_graph=_m365(),
            slack_workspace=True,
            slack_transport=_slack(),
            semantic_store=None,
        )
        assert report.total >= 1  # detection still runs offline
        await assert_no_entities(store, tenant_id="t_off", categories=_CATEGORIES)
