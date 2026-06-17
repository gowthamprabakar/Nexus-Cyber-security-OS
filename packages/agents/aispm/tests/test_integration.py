"""AI-SPM integration tests (D.11 PR6).

1. All three clouds + a gated probe in one run → merged OCSF 2003 + 2004 findings + a
   coherent AI subgraph (AI_SERVICE/AI_MODEL + HOSTS_AI/EXPOSES_MODEL) on a real
   in-memory SemanticStore.
2. Two tenants scanned separately → each run's graph is tenant-scoped (no leakage).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from aispm.agent import run
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.models import Base
from charter.memory.semantic import SemanticStore
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio

_PERMITTED = ["discover_aws_ai", "discover_azure_ai", "discover_gcp_ai", "probe_garak"]


def _contract(tmp_path: Path, *, customer_id: str = "cust_test") -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="aispm",
        customer_id=customer_id,
        task="AI posture scan",
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


class _FakeAws:
    def sagemaker_endpoints(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "prod",
                "data_capture_enabled": False,
                "kms_encrypted": True,
                "network_isolated": False,
                "model_name": "m1",
            }
        ]

    def sagemaker_notebooks(self) -> list[dict[str, Any]]:
        return []

    def bedrock_logging_enabled(self) -> bool | None:
        return True

    def bedrock_guardrail_count(self) -> int:
        return 1


class _FakeAzure:
    def openai_accounts(self) -> list[dict[str, Any]]:
        return [{"name": "oai", "public_network_access": True, "cmk_encrypted": True}]


class _FakeGcp:
    def vertex_endpoints(self) -> list[dict[str, Any]]:
        return [{"name": "ep", "public": True, "cmk_encrypted": True, "psc_enabled": True}]


class _FakeGarak:
    async def probe(self, *, target: str) -> list[dict[str, Any]]:
        return [{"entry_type": "eval", "probe": "dan", "detector": "dan", "passed": 3, "total": 10}]


@pytest_asyncio.fixture
async def store() -> AsyncIterator[SemanticStore]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    yield SemanticStore(factory)
    await engine.dispose()


async def test_all_clouds_plus_probe_one_run(tmp_path: Path, store: SemanticStore) -> None:
    report = await run(
        _contract(tmp_path),
        aws_account_id="111122223333",
        aws_reader=_FakeAws(),
        azure_subscription_id="sub-1",
        azure_reader=_FakeAzure(),
        gcp_project_id="proj-1",
        gcp_reader=_FakeGcp(),
        probe_target="anthropic.claude",
        garak_runner=_FakeGarak(),
        semantic_store=store,
    )
    doc = json.loads((tmp_path / "ws" / "findings.json").read_text())
    classes = {f["class_uid"] for f in doc["findings"]}
    assert 2003 in classes and 2004 in classes  # posture + prompt-injection
    assert report.total >= 4

    services = await store.list_entities_by_type(tenant_id="cust_test", entity_type="ai_service")
    ext = {s.external_id for s in services}
    assert "sagemaker:111122223333:prod" in ext
    assert "azure_openai:sub-1:oai" in ext
    assert "vertex:proj-1:ep" in ext


async def test_two_tenants_isolated_in_graph(tmp_path: Path, store: SemanticStore) -> None:
    for cust in ("cust_a", "cust_b"):
        await run(
            _contract(tmp_path / cust, customer_id=cust),
            aws_account_id="111122223333",
            aws_reader=_FakeAws(),
            semantic_store=store,
        )
    a = await store.list_entities_by_type(tenant_id="cust_a", entity_type="ai_service")
    b = await store.list_entities_by_type(tenant_id="cust_b", entity_type="ai_service")
    assert {s.external_id for s in a} == {s.external_id for s in b}
    assert a[0].entity_id != b[0].entity_id  # distinct tenant partitions
