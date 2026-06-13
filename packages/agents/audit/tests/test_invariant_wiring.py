"""Phase C SS3 — F.6 run() makes assert_audit_readonly + assert_admin_for_cross_tenant load-bearing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from audit import agent as agent_mod
from audit.agent import run as audit_run
from audit.readonly import UnauthorizedAuditMutationError, assert_audit_readonly
from audit.store import AuditStore
from audit.tenant_authz import (
    CrossTenantAuditAuthorizationError,
    assert_admin_for_cross_tenant,
    cross_tenant_query,
)
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.models import Base
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_TENANT = "01HV0T0000000000000000TENA"


@pytest_asyncio.fixture
async def audit_store() -> AuditStore:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(engine, expire_on_commit=False)
    return AuditStore(factory)


def _contract(workspace: Path) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        source_agent="supervisor",
        target_agent="audit",
        customer_id=_TENANT,
        task="audit query",
        required_outputs=["report.md", "events.json"],
        budget=BudgetSpec(
            llm_calls=1, tokens=1, wall_clock_sec=60.0, cloud_api_calls=10, mb_written=10
        ),
        permitted_tools=["audit_jsonl_read", "episode_audit_read"],
        completion_condition="report.md exists",
        escalation_rules=[],
        workspace=str(workspace / "ws"),
        persistent_root=str(workspace / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def test_readonly_guard_correctness() -> None:
    assert_audit_readonly("verify")
    assert_audit_readonly("query")
    with pytest.raises(UnauthorizedAuditMutationError):
        assert_audit_readonly("delete")


def test_cross_tenant_guard_correctness() -> None:
    # single-tenant passes for any role; multi-tenant needs admin.
    assert_admin_for_cross_tenant(cross_tenant_query(tenant_ids=[_TENANT]), "auditor")
    with pytest.raises(CrossTenantAuditAuthorizationError):
        assert_admin_for_cross_tenant(cross_tenant_query(all_tenants=True), "auditor")
    assert_admin_for_cross_tenant(cross_tenant_query(all_tenants=True), "admin")  # admin ok


@pytest.mark.asyncio
async def test_run_invokes_both_guards(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, audit_store: AuditStore
) -> None:
    ro_ops: list[str] = []
    xt_calls: list[str] = []

    real_ro = assert_audit_readonly
    real_xt = assert_admin_for_cross_tenant

    def spy_ro(op: str) -> None:
        ro_ops.append(op)
        real_ro(op)

    def spy_xt(query: object, role: str) -> None:
        xt_calls.append(role)
        real_xt(query, role)  # type: ignore[arg-type]

    monkeypatch.setattr(agent_mod, "assert_audit_readonly", spy_ro)
    monkeypatch.setattr(agent_mod, "assert_admin_for_cross_tenant", spy_xt)

    await audit_run(
        _contract(tmp_path), audit_store=audit_store, sources=(), memory_session_factory=None
    )
    assert "verify" in ro_ops and "query" in ro_ops
    assert xt_calls == ["auditor"]  # single-tenant run, default non-admin role -> passes
