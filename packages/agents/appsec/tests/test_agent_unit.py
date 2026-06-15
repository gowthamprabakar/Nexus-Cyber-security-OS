"""AppSec agent run() wiring tests (D.14 v0.1)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from appsec.agent import build_registry, run
from appsec.schemas import RepoRef
from appsec.tools.scm_connector import StaticScmConnector
from charter.contract import BudgetSpec, ExecutionContract

pytestmark = pytest.mark.asyncio


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="appsec",
        customer_id="cust_test",
        task="Discover source repositories",
        required_outputs=["repo_inventory.json", "findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=1, tokens=1, wall_clock_sec=60.0, cloud_api_calls=100, mb_written=10
        ),
        permitted_tools=["discover_repositories"],
        completion_condition="repo_inventory.json AND findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _repo(owner: str, name: str) -> RepoRef:
    return RepoRef(
        host="github",
        owner=owner,
        name=name,
        clone_url=f"https://github.com/{owner}/{name}.git",
        visibility="private",
    )


def test_build_registry_has_discover_tool() -> None:
    assert "discover_repositories" in build_registry().known_tools()


async def test_run_empty_discovery_writes_artifacts(tmp_path: Path) -> None:
    inventory = await run(_contract(tmp_path))
    assert inventory.total == 0
    ws = tmp_path / "ws"
    assert (ws / "repo_inventory.json").exists()
    assert (ws / "findings.json").exists()
    assert (ws / "summary.md").exists()
    findings = json.loads((ws / "findings.json").read_text())
    assert findings["findings"] == []


async def test_run_discovers_injected_repos(tmp_path: Path) -> None:
    connector = StaticScmConnector([_repo("acme", "api"), _repo("acme", "web")])
    inventory = await run(_contract(tmp_path), scm_connector=connector)
    assert inventory.total == 2
    payload = json.loads((tmp_path / "ws" / "repo_inventory.json").read_text())
    slugs = {r["host"] + "/" + r["owner"] + "/" + r["name"] for r in payload["repositories"]}
    assert slugs == {"github/acme/api", "github/acme/web"}
    assert payload["agent"] == "appsec"
