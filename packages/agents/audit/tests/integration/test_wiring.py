"""Fleet Test Level 1 — audit (F.6) wiring smoke.

Tier B (institutional-integrity orchestration, ALWAYS-ON class). F.6 does not scan or detect:
it INGESTS other agents' audit chains from jsonl sources (+ optionally F.5 episodes), verifies
chain integrity, and emits OCSF 6003 records. It takes an `audit_store` (NOT a semantic_store),
has NO kg_writer, and produces its 6003 output through the F.6 aggregation/tamper path — NOT a
findings.json.

L1 is SMOKE, not capability — proves plumbing only (run completes, ingest happened, chain
integrity verified, 6003 emission shape correct). Tamper-detection precision is L2.

Tier-B assertion subset (every omission documented, swiss-bar #5/#12):
  * ASSERTS: run completes (AuditQueryResult), ingest landed (>=1 event queryable for the
    tenant), the chain verifies clean for an intact source, OCSF 6003 emission shape is valid
    (via the public AuditEvent.to_ocsf() + emit_tamper_alerts F.6 paths), the Charter workspace
    chain (audit.jsonl) hash-verifies, and tenant isolation (a second tenant's ingest does not
    appear in the first tenant's query).
  * OMITS the shared fleet_testkit.assert_ocsf_valid helper: that helper is envelope-strict
    (requires a `nexus_envelope` key). F.6's 6003 records are BARE OCSF v1.3 — F.6 does not wrap
    them in a Nexus envelope (it is not a fabric `findings.>` publisher; it emits via the
    aggregation/tamper API). We validate the 6003 structure directly (class_uid + actor + api).
    Documented deviation, not a skipped check.
  * OMITS findings.json assertions: F.6 emits no findings.json — its artifacts are report.md +
    events.json (the AuditQueryResult) + audit.jsonl. Documented.
  * OMITS all kg assertions: F.6 has no kg_writer and takes no semantic_store. Documented;
    asserting one would be a fake-green.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from audit.agent import run
from audit.store import AuditStore
from audit.tamper.alert import emit_tamper_alerts
from charter.audit import AuditLog
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory.models import Base
from fleet_testkit import assert_audit_chain
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# F.6's AuditEvent requires ULID-shaped (26-char) tenant ids; plain "tenant_a" is rejected and
# the forgiving jsonl reader would silently drop every event. Use valid 26-char ULIDs.
_TENANT_A = "01HV0T0000000000000000TENA"
_TENANT_B = "01HV0T0000000000000000TENB"
_OCSF_CLASS = 6003  # API Activity (audit.schemas — F.6 6003 emitter)


@pytest_asyncio.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def audit_store(session_factory: async_sessionmaker[AsyncSession]) -> AuditStore:
    return AuditStore(session_factory)


def _contract(workspace_root: Path, *, customer_id: str, delegation_id: str) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id=delegation_id,
        source_agent="supervisor",
        target_agent="audit",
        customer_id=customer_id,
        task="fleet-test L1 wiring smoke for audit",
        required_outputs=["report.md", "events.json"],
        budget=BudgetSpec(
            llm_calls=5,
            tokens=10_000,
            wall_clock_sec=60.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=["audit_jsonl_read", "episode_audit_read"],
        completion_condition="report.md AND events.json exist",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _seed_source_jsonl(path: Path, *, agent: str, n: int = 3) -> Path:
    """Write a real, well-chained audit.jsonl source via charter.audit.AuditLog (the exact
    producer F.6 ingests in production — swiss-bar #3, not mock theater)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    log = AuditLog(path, agent=agent, run_id=f"{agent}-run")
    for i in range(n):
        log.append(action=f"finding.created.{i}", payload={"i": i})
    return path


@pytest.mark.asyncio
async def test_wiring_audit(tmp_path: Path, audit_store: AuditStore) -> None:
    """Tier B orchestration: run completes · ingest landed · chain verifies · 6003 emission
    shape valid · workspace audit chain hash-verifies. (No findings.json / kg — see docstring.)"""
    src_a = _seed_source_jsonl(
        tmp_path / "a" / "src" / "cloud_posture.jsonl", agent="cloud_posture"
    )
    contract_a = _contract(
        tmp_path / "a", customer_id=_TENANT_A, delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ"
    )
    result_a = await run(contract_a, audit_store=audit_store, sources=(src_a,))

    # run-completes + ingest landed (events queryable for the tenant).
    assert result_a.total >= 1, "F.6 ingested no events from the seeded source"

    # OCSF 6003 emission shape (the F.6 path AuditEvent.to_ocsf produces; bare OCSF, no envelope).
    for event in result_a.events:
        ocsf: dict[str, Any] = event.to_ocsf()
        assert ocsf.get("class_uid") == _OCSF_CLASS, (
            f"OCSF class_uid: expected {_OCSF_CLASS}, got {ocsf.get('class_uid')!r}"
        )
        assert ocsf.get("actor", {}).get("user", {}).get("name"), "6003 actor.user.name missing"
        assert ocsf.get("api", {}).get("operation"), "6003 api.operation missing"
        assert ocsf.get("unmapped", {}).get("tenant_id") == _TENANT_A, "6003 tenant mismatch"

    # 6003 tamper-detection emission shape: inject a tamper into a chain and assert F.6 surfaces
    # an OCSF 6003 alert (WI-F9 always-alerts; the tamper path also emits class_uid 6003).
    tampered = list(result_a.events)
    tampered[1] = tampered[1].model_copy(update={"action": "FORGED"})
    alerts = emit_tamper_alerts("cloud_posture-chain", tampered)
    assert alerts, "tamper injected but F.6 emitted no alert"
    assert alerts[0]["class_uid"] == _OCSF_CLASS, "tamper alert is not OCSF 6003"

    # Charter workspace audit chain hash-verifies (F.6's own per-run invocation chain).
    assert_audit_chain(tmp_path / "a" / "ws" / "audit.jsonl")

    # tenant isolation: a second tenant's ingest does not appear in tenant_a's query result.
    src_b = _seed_source_jsonl(tmp_path / "b" / "src" / "compliance.jsonl", agent="compliance")
    contract_b = _contract(
        tmp_path / "b", customer_id=_TENANT_B, delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0"
    )
    result_b = await run(contract_b, audit_store=audit_store, sources=(src_b,))
    assert result_b.total >= 1
    # Re-query tenant_a after tenant_b's ingest — still scoped to tenant_a's source only.
    result_a2 = await run(contract_a, audit_store=audit_store, sources=(src_a,))
    a_agents = {e.agent_id for e in result_a2.events}
    assert "compliance" not in a_agents, (
        f"cross-tenant leak: tenant_a query returned tenant_b's agents: {a_agents}"
    )
