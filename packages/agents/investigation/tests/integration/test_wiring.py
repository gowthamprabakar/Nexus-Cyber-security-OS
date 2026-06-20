"""Fleet Test Level 1 — investigation (D.7 CDR) wiring smoke.

Tier B (read-only orchestrator). Investigation reads the graph + sibling findings.json +
the audit trail, synthesizes an incident, and emits OCSF 2005. It has NO kg_writer — it never
writes the graph. `run(contract, *, audit_store, semantic_store, ...)` requires BOTH stores as
keyword args; the semantic_store is a hard wiring dependency.

L1 is SMOKE, not capability — proves plumbing only (run completes, OCSF 2005 valid, audit
chain clean, tenant isolated). Incident-quality / hypothesis precision is L2.

Tier-B assertion subset (every omission documented, swiss-bar #5/#12):
  * ASSERTS: run completes (returns IncidentReport), OCSF 2005 structurally valid, audit chain
    hash-verifies, two-tenant isolation on the EMITTED incident (each run stamps its own
    tenant_id into the OCSF unmapped block → disjoint across tenants). The semantic_store is
    seeded + wired into the run so the graph-read dependency is exercised end-to-end.
  * OMITS assert_entity_written: D.7 is a read-only orchestrator with no kg_writer — there is
    no node-type for it to write. Asserting a write would be a fake-green.
  * OMITS the shared fleet_testkit.assert_ocsf_valid helper: that helper is envelope-strict
    (it requires a `nexus_envelope` key). D.7's `incident_report.json` is BARE OCSF v1.3 —
    D.7 is not a fabric `findings.>` publisher, so its artifact carries no Nexus envelope. We
    therefore validate the OCSF 2005 structure directly (class_uid + non-empty finding_info.uid
    + tenant on the unmapped block). Documented deviation, not a skipped check.
  * PARTIAL on "assert it READ the seeded graph": the v0.1 driver only walks the graph when a
    sub-investigation scope carries a `seed_entity_id`, which the driver does not populate in
    v0.1 (graph-walk seeds are a Phase-1c driver hook). So a concrete graph READ is not
    reachable through run() at L1. We seed the store + wire it in to prove the dependency is
    accepted and healthy; the read itself is asserted at the tool level elsewhere (unit tests
    for memory_neighbors_walk). Documented; not faked.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from audit.schemas import AuditEvent
from audit.store import AuditStore
from charter.contract import BudgetSpec, ExecutionContract
from charter.memory import SemanticStore
from charter.memory.models import Base
from fleet_testkit import assert_audit_chain
from investigation.agent import run as investigation_run
from investigation.schemas import IncidentReport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_OCSF_CLASS = 2005  # Incident Finding (investigation.schemas)
_TENANT_A = "01HV0T0000000000000000TENA"
_TENANT_B = "01HV0T0000000000000000TENB"


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


@pytest_asyncio.fixture
async def semantic_store(session_factory: async_sessionmaker[AsyncSession]) -> SemanticStore:
    return SemanticStore(session_factory)


def _contract(workspace_root: Path, *, customer_id: str, delegation_id: str) -> ExecutionContract:
    return ExecutionContract(
        schema_version="0.1",
        delegation_id=delegation_id,
        source_agent="supervisor",
        target_agent="investigation",
        customer_id=customer_id,
        task="fleet-test L1 wiring smoke for investigation",
        required_outputs=[
            "incident_report.json",
            "timeline.json",
            "hypotheses.md",
            "containment_plan.yaml",
        ],
        budget=BudgetSpec(
            llm_calls=30,
            tokens=60_000,
            wall_clock_sec=600.0,
            cloud_api_calls=10,
            mb_written=10,
        ),
        permitted_tools=[
            "audit_trail_query",
            "memory_neighbors_walk",
            "find_related_findings",
            "extract_iocs",
            "map_to_mitre",
            "reconstruct_timeline",
            "synthesize_hypotheses",
        ],
        completion_condition="incident_report.json exists",
        escalation_rules=[],
        workspace=str(workspace_root / "ws"),
        persistent_root=str(workspace_root / "p"),
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def _audit_event(*, tenant_id: str, seed: int) -> AuditEvent:
    return AuditEvent(
        tenant_id=tenant_id,
        correlation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ",
        agent_id="cloud_posture",
        action="finding.created",
        payload={"seed": seed},
        previous_hash=f"{seed:064x}",
        entry_hash=f"{seed + 1:064x}",
        emitted_at=datetime(2026, 5, 12, tzinfo=UTC),
        source=f"jsonl:fixture/{seed}",
    )


async def _seed_graph(store: SemanticStore, *, tenant_id: str) -> None:
    """Seed a small two-node subgraph so the wired semantic_store is non-empty + healthy."""
    a = await store.upsert_entity(tenant_id=tenant_id, entity_type="host", external_id="host-a")
    b = await store.upsert_entity(tenant_id=tenant_id, entity_type="host", external_id="host-b")
    await store.add_relationship(
        tenant_id=tenant_id, src_entity_id=a, dst_entity_id=b, relationship_type="LINKS"
    )


def _ocsf(workspace: Path) -> dict[str, Any]:
    return json.loads((workspace / "incident_report.json").read_text())


def _assert_ocsf_2005(payload: dict[str, Any], *, tenant_id: str) -> None:
    """D.7-specific OCSF 2005 structural check (bare OCSF, no Nexus envelope — see docstring)."""
    assert payload.get("class_uid") == _OCSF_CLASS, (
        f"OCSF class_uid: expected {_OCSF_CLASS}, got {payload.get('class_uid')!r}"
    )
    finding_info = payload.get("finding_info")
    assert isinstance(finding_info, dict) and finding_info.get("uid"), (
        f"OCSF finding_info.uid must be non-empty, got {finding_info!r}"
    )
    assert payload.get("unmapped", {}).get("tenant_id") == tenant_id, (
        f"OCSF unmapped.tenant_id must be {tenant_id!r}, got {payload.get('unmapped')!r}"
    )


@pytest.mark.asyncio
async def test_wiring_investigation(
    tmp_path: Path, audit_store: AuditStore, semantic_store: SemanticStore
) -> None:
    """Tier B read-only orchestrator: run completes · OCSF 2005 valid · audit chain
    hash-verifies · two-tenant isolation. (No kg-write assertion — D.7 has no kg_writer.)"""
    # tenant A — seed the audit trail + graph, then wire both stores into the run.
    await audit_store.ingest(
        tenant_id=_TENANT_A, events=(_audit_event(tenant_id=_TENANT_A, seed=1),)
    )
    await _seed_graph(semantic_store, tenant_id=_TENANT_A)
    ws_a = tmp_path / "a"
    contract_a = _contract(ws_a, customer_id=_TENANT_A, delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHFZ")
    report_a = await investigation_run(
        contract_a,
        audit_store=audit_store,
        semantic_store=semantic_store,
        llm_provider=None,
        sibling_workspaces=(),
        since=None,
        until=None,
    )

    assert isinstance(report_a, IncidentReport)
    ocsf_a = _ocsf(ws_a / "ws")
    _assert_ocsf_2005(ocsf_a, tenant_id=_TENANT_A)
    assert_audit_chain(ws_a / "ws" / "audit.jsonl")

    # tenant isolation: a second tenant's run stamps its own tenant into the emitted OCSF;
    # the two emitted incident ids + tenant tags are disjoint.
    await audit_store.ingest(
        tenant_id=_TENANT_B, events=(_audit_event(tenant_id=_TENANT_B, seed=5),)
    )
    await _seed_graph(semantic_store, tenant_id=_TENANT_B)
    ws_b = tmp_path / "b"
    contract_b = _contract(ws_b, customer_id=_TENANT_B, delegation_id="01J7M3X9Z1K8RPVQNH2T8DBHG0")
    await investigation_run(
        contract_b,
        audit_store=audit_store,
        semantic_store=semantic_store,
        llm_provider=None,
        sibling_workspaces=(),
        since=None,
        until=None,
    )
    ocsf_b = _ocsf(ws_b / "ws")
    _assert_ocsf_2005(ocsf_b, tenant_id=_TENANT_B)
    assert ocsf_a["finding_info"]["uid"] != ocsf_b["finding_info"]["uid"], (
        "two tenants emitted the same incident uid — isolation breach"
    )
