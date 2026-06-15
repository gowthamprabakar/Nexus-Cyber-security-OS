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
from appsec.tools.gitleaks_runner import GitleaksResult
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
        permitted_tools=[
            "discover_repositories",
            "run_checkov",
            "run_gitleaks",
            "clone_repository",
        ],
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

    async def empty_gitleaks(repo_path: str, **_: object) -> GitleaksResult:
        return GitleaksResult(payload=[])

    monkeypatch.setattr(agent_mod, "run_checkov", fake_checkov)
    monkeypatch.setattr(agent_mod, "run_gitleaks", empty_gitleaks)
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


async def test_run_gitleaks_writes_redacted_code_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """gitleaks hits → code_secrets.json handoff (redacted, ADR-015 → DSPM)."""
    plaintext = "AKIAIOSFODNN7EXAMPLE"  # AWS docs example, test fixture

    async def empty_checkov(repo_path: str, **_: object) -> CheckovResult:
        return CheckovResult(payload={})

    async def fake_gitleaks(repo_path: str, **_: object) -> GitleaksResult:
        return GitleaksResult(
            payload=[
                {
                    "RuleID": "aws-access-token",
                    "Description": "AWS Access Token",
                    "File": "src/config.py",
                    "StartLine": 12,
                    "EndLine": 12,
                    "Secret": plaintext,
                    "Match": f"KEY={plaintext}",
                }
            ]
        )

    monkeypatch.setattr(agent_mod, "run_checkov", empty_checkov)
    monkeypatch.setattr(agent_mod, "run_gitleaks", fake_gitleaks)
    repo = RepoRef(
        host="github",
        owner="acme",
        name="api",
        clone_url="https://github.com/acme/api.git",
        local_path=str(tmp_path / "checkout"),
    )
    await run(_contract(tmp_path), scm_connector=StaticScmConnector([repo]))

    secrets_path = tmp_path / "ws" / "code_secrets.json"
    assert secrets_path.exists()
    text = secrets_path.read_text()
    assert plaintext not in text  # redaction holds end-to-end
    payload = json.loads(text)
    assert payload["agent"] == "appsec"
    assert payload["secrets"][0]["rule_id"] == "aws-access-token"


async def test_run_clone_root_clones_then_scans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """clone_root set → discovered repo (no local_path) is cloned, then scanned."""
    cloned_dest = tmp_path / "clones" / "github" / "acme" / "api"

    async def fake_clone(args: list[str], timeout: float) -> int:
        return 0

    seen_paths: list[str] = []

    async def spy_checkov(repo_path: str, **_: object) -> CheckovResult:
        seen_paths.append(repo_path)
        return CheckovResult(payload={})

    async def empty_gitleaks(repo_path: str, **_: object) -> GitleaksResult:
        return GitleaksResult(payload=[])

    monkeypatch.setattr(agent_mod, "run_checkov", spy_checkov)
    monkeypatch.setattr(agent_mod, "run_gitleaks", empty_gitleaks)

    # repo discovered WITHOUT a local_path (as a live connector returns it)
    repo = RepoRef(
        host="github", owner="acme", name="api", clone_url="https://github.com/acme/api.git"
    )
    inventory = await run(
        _contract(tmp_path),
        scm_connector=StaticScmConnector([repo]),
        clone_root=tmp_path / "clones",
        clone_runner=fake_clone,
    )
    # The inventory repo now carries the cloned local_path, and the scanner saw it.
    assert inventory.repositories[0].local_path == str(cloned_dest)
    assert seen_paths == [str(cloned_dest)]


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
