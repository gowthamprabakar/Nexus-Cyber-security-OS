"""AppSec agent run() wiring tests (D.14 v0.1)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from appsec import agent as agent_mod
from appsec.agent import build_registry, run
from appsec.schemas import RepoRef
from appsec.tools.checkov_runner import CheckovResult
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
        permitted_tools=["discover_repositories", "run_checkov"],
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


async def test_run_checkov_emits_ocsf_2003(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A repo with a local_path → Checkov runs → findings.json carries OCSF 2003."""

    async def fake_checkov(repo_path: str, **_: object) -> CheckovResult:
        return CheckovResult(
            payload={
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_AWS_20",
                            "check_name": "S3 public ACL",
                            "file_path": "/main.tf",
                            "file_line_range": [1, 5],
                            "resource": "aws_s3_bucket.x",
                            "severity": "HIGH",
                        }
                    ]
                }
            }
        )

    monkeypatch.setattr(agent_mod, "run_checkov", fake_checkov)
    repo = RepoRef(
        host="github",
        owner="acme",
        name="api",
        clone_url="https://github.com/acme/api.git",
        local_path=str(tmp_path / "checkout"),
    )
    await run(_contract(tmp_path), scm_connector=StaticScmConnector([repo]))

    findings = json.loads((tmp_path / "ws" / "findings.json").read_text())["findings"]
    assert len(findings) == 1
    assert findings[0]["class_uid"] == 2003
    assert findings[0]["finding_info"]["types"] == ["appsec_iac_misconfiguration"]
    assert findings[0]["compliance"]["control"] == "CKV_AWS_20"


async def test_run_skips_checkov_without_local_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repo with no local_path → Checkov not invoked → empty findings."""

    async def boom(repo_path: str, **_: object) -> CheckovResult:
        raise AssertionError("checkov must not run for a repo without local_path")

    monkeypatch.setattr(agent_mod, "run_checkov", boom)
    repo = RepoRef(host="github", owner="acme", name="api", clone_url="https://x/y.git")
    await run(_contract(tmp_path), scm_connector=StaticScmConnector([repo]))
    assert json.loads((tmp_path / "ws" / "findings.json").read_text())["findings"] == []
