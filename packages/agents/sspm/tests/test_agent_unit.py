"""Unit tests for the SSPM agent driver (D.10).

PR1 pinned the skeleton + output contract. PR2 wires the GitHub-org connector through
the charter proxy; the connector HTTP seam is faked here (no live GitHub).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from charter import ToolRegistry
from charter.contract import BudgetSpec, ExecutionContract
from sspm.agent import build_registry, run
from sspm.tools.github_org import GITHUB_API


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="sspm",
        customer_id="cust_test",
        task="SaaS posture scan",
        required_outputs=["findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=1, tokens=1, wall_clock_sec=60.0, cloud_api_calls=100, mb_written=10
        ),
        permitted_tools=["read_github_org", "read_m365_tenant", "read_slack_workspace"],
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
        return self.routes.get(url, (404, {}, None))


def test_build_registry_registers_github_connector() -> None:
    reg = build_registry()
    assert isinstance(reg, ToolRegistry)
    assert "read_github_org" in reg.known_tools()


@pytest.mark.asyncio
async def test_no_connector_writes_empty_artifacts(tmp_path: Path) -> None:
    report = await run(_contract(tmp_path))  # no github_org → no connector
    assert report.total == 0
    doc = json.loads((tmp_path / "ws" / "findings.json").read_text())
    assert doc["findings"] == []
    assert "SaaS Security Posture" in (tmp_path / "ws" / "summary.md").read_text()


class _FakeGraph:
    def __init__(
        self,
        collections: dict[str, list[dict[str, Any]]],
        objects: dict[str, dict[str, Any]],
    ) -> None:
        self._c = collections
        self._o = objects

    async def get_all(self, resource: str, *, select: str | None = None) -> list[dict[str, Any]]:
        return self._c.get(resource, [])

    async def get_one(self, resource: str) -> dict[str, Any]:
        return self._o.get(resource, {})


@pytest.mark.asyncio
async def test_m365_connector_emits_findings(tmp_path: Path) -> None:
    graph = _FakeGraph(
        collections={"identity/conditionalAccessPolicies": []},
        objects={"policies/identitySecurityDefaultsEnforcementPolicy": {"isEnabled": False}},
    )
    report = await run(_contract(tmp_path), m365_tenant="contoso", m365_graph=graph)
    # security defaults disabled + zero conditional access = 2 findings.
    assert report.total == 2
    doc = json.loads((tmp_path / "ws" / "findings.json").read_text())
    types = {f["finding_info"]["types"][0] for f in doc["findings"]}
    assert "sspm_m365_security_defaults_disabled" in types
    assert "sspm_m365_no_conditional_access" in types


@pytest.mark.asyncio
async def test_slack_connector_emits_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEXUS_SSPM_SLACK_TOKEN", "xoxb-test")
    routes = {
        "https://slack.com/api/team.info": (
            200,
            {},
            {"ok": True, "team": {"id": "T01", "name": "Acme"}},
        ),
        "https://slack.com/api/users.list?limit=200": (
            200,
            {},
            {
                "ok": True,
                "members": [{"id": "U1", "is_restricted": True, "has_2fa": False}],
                "response_metadata": {},
            },
        ),
        "https://slack.com/api/admin.apps.approved.list?limit=100": (
            200,
            {},
            {"ok": False, "error": "not_an_enterprise_install"},
        ),
    }
    report = await run(_contract(tmp_path), slack_workspace=True, slack_transport=_FakeHttp(routes))
    # 1 member without 2FA + 1 guest = 2 findings.
    assert report.total == 2
    doc = json.loads((tmp_path / "ws" / "findings.json").read_text())
    types = {f["finding_info"]["types"][0] for f in doc["findings"]}
    assert "sspm_slack_members_without_2fa" in types
    assert "sspm_slack_external_guests" in types


@pytest.mark.asyncio
async def test_github_connector_emits_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEXUS_SSPM_GITHUB_TOKEN", "ghp_test_token")
    routes = {
        f"{GITHUB_API}/orgs/acme": (
            200,
            {},
            {"two_factor_requirement_enabled": False, "default_repository_permission": "read"},
        ),
        f"{GITHUB_API}/orgs/acme/repos?per_page=100": (
            200,
            {},
            [{"name": "web", "private": False, "default_branch": "main"}],
        ),
        f"{GITHUB_API}/repos/acme/web/branches/main/protection": (404, {}, None),
    }
    report = await run(_contract(tmp_path), github_org="acme", github_transport=_FakeHttp(routes))

    # 2FA-disabled (org) + public repo + unprotected default branch = 3 findings.
    assert report.total == 3
    doc = json.loads((tmp_path / "ws" / "findings.json").read_text())
    types = {f["finding_info"]["types"][0] for f in doc["findings"]}
    assert "sspm_github_org_2fa_disabled" in types
    assert "sspm_github_repo_public" in types
    assert "sspm_github_default_branch_unprotected" in types
    assert all(f["class_uid"] == 2003 for f in doc["findings"])
