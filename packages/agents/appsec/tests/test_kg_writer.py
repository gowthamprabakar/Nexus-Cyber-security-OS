"""Tests for the AppSec knowledge-graph writer (v0.4 Stage 1.6).

End-to-end through ``agent.run()`` against a real in-memory ``SemanticStore``: the
code-side inventory AppSec discovers (repositories + IaC artifacts) lands in the
fleet graph, with ``DEFINED_IN`` linking artifact → repository. Opt-in: default
(no store) writes nothing.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from appsec import agent as agent_mod
from appsec.agent import run
from appsec.schemas import RepoRef
from appsec.tools.checkov_runner import CheckovResult
from appsec.tools.gitleaks_runner import GitleaksResult
from appsec.tools.scm_connector import StaticScmConnector
from appsec.tools.semgrep_runner import SemgrepResult
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio

_TENANT = "cust_test"


def _contract(tmp_path: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="appsec",
        customer_id=_TENANT,
        task="Scan repos",
        required_outputs=["repo_inventory.json", "findings.json", "summary.md"],
        budget=BudgetSpec(
            llm_calls=1, tokens=1, wall_clock_sec=60.0, cloud_api_calls=100, mb_written=10
        ),
        permitted_tools=["discover_repositories", "run_checkov", "run_gitleaks", "run_semgrep"],
        completion_condition="repo_inventory.json AND findings.json AND summary.md exist",
        escalation_rules=[],
        workspace=str(tmp_path / "ws"),
        persistent_root=str(tmp_path / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _repo(tmp_path: Path) -> RepoRef:
    return RepoRef(
        host="github",
        owner="acme",
        name="api",
        clone_url="https://github.com/acme/api.git",
        local_path=str(tmp_path / "checkout"),
    )


def _wire_scanners(monkeypatch: pytest.MonkeyPatch) -> None:
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

    async def empty_semgrep(repo_path: str, **_: object) -> SemgrepResult:
        return SemgrepResult(payload={})

    monkeypatch.setattr(agent_mod, "run_checkov", fake_checkov)
    monkeypatch.setattr(agent_mod, "run_gitleaks", empty_gitleaks)
    monkeypatch.setattr(agent_mod, "run_semgrep", empty_semgrep)


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


async def test_run_with_store_writes_repo_and_iac_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: SemanticStore
) -> None:
    _wire_scanners(monkeypatch)
    await run(
        _contract(tmp_path),
        scm_connector=StaticScmConnector([_repo(tmp_path)]),
        semantic_store=store,
    )

    repos = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="code_repository")
    assert len(repos) == 1
    assert repos[0].external_id == "github/acme/api"

    artifacts = await store.list_entities_by_type(tenant_id=_TENANT, entity_type="iac_artifact")
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact.properties["file"] == "main.tf"

    # DEFINED_IN: artifact → repository is traversable.
    neighbors = await store.neighbors(tenant_id=_TENANT, entity_id=artifact.entity_id, depth=1)
    assert any(n.entity_type == "code_repository" for n in neighbors)


async def test_run_without_store_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: SemanticStore
) -> None:
    _wire_scanners(monkeypatch)
    await run(_contract(tmp_path), scm_connector=StaticScmConnector([_repo(tmp_path)]))
    assert await store.list_entities_by_type(tenant_id=_TENANT, entity_type="code_repository") == []
