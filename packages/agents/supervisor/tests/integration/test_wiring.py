"""Fleet Test Level 1 — supervisor (Agent #0) wiring smoke.

Tier B (dispatcher / orchestration). The supervisor is NOT a sensor: it routes IncomingTask
envelopes to specialist agents, dispatches signed DelegationContracts, and records the outcome.
It emits NO OCSF, has NO kg_writer, and reads NO semantic_store. Its run() signature is its
own (`run(*, customer_id, workspace_root, routing_rules, triggers, invoker, ...)`), not the
shared `(contract, *, semantic_store)` shape.

L1 is SMOKE, not capability — proves plumbing only (run/dispatch completes, routing-decision
output shape correct, audit chain clean, tenant carried). Routing-policy correctness is L2.

Tier-B assertion subset (every omission documented, swiss-bar #5/#12):
  * ASSERTS: run completes (SupervisorReport), routing-decision output shape (a RoutingMatch
    for the matched task + a dispatched DelegationOutcome with status OK), the workspace audit
    chain hash-verifies, and tenant isolation (each tenant's report carries only its own
    customer_id, and the two ticks write to disjoint per-tenant workspaces with their own
    audit chains — the supervisor is single-tenant-per-tick by construction).
  * OMITS the shared assert_ocsf_valid / findings.json assertions: the supervisor emits no OCSF
    and writes no findings.json (its artifacts are supervisor_report.md + audit.jsonl). It is a
    dispatcher, not a detector. Documented; asserting an OCSF finding would be a fake-green.
  * OMITS all kg assertions (assert_entity_written / two_tenant_disjoint over NodeCategory):
    the supervisor has no kg_writer and its semantic_store arg is an unused v0.1 placeholder
    (`del semantic_store`). There is no graph write/read to assert. Documented.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fleet_testkit import assert_audit_chain
from supervisor.agent import run
from supervisor.schemas import (
    DelegationStatus,
    IncomingTask,
    RoutingMatch,
    RoutingRule,
    SupervisorReport,
    TriggerSource,
)

_NOW = datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC)


def _rule() -> RoutingRule:
    return RoutingRule(
        rule_id="r-compliance",
        target_agent="compliance",
        target_agent_declared="compliance",
        permitted_tools=("read_cis_aws_benchmark",),
    )


def _task(*, customer_id: str) -> IncomingTask:
    return IncomingTask(
        task_id="task-1",
        customer_id=customer_id,
        trigger_source=TriggerSource.OPERATOR_CLI,
        target_agent="compliance",
        description="fleet-test L1 wiring smoke trigger",
        received_at=_NOW,
    )


@pytest.mark.asyncio
async def test_wiring_supervisor(tmp_path: Path) -> None:
    """Tier B dispatcher: run completes · routing-decision shape valid · dispatch recorded ·
    audit chain hash-verifies · tenant carried. (No OCSF / no graph — see module docstring.)"""
    ws_a = tmp_path / "a"
    report_a = await run(
        customer_id="tenant_a",
        workspace_root=ws_a,
        routing_rules=(_rule(),),
        triggers=(_task(customer_id="tenant_a"),),
    )

    # run-completes + routing-decision output shape.
    assert isinstance(report_a, SupervisorReport)
    assert report_a.customer_id == "tenant_a"
    assert report_a.total_triggers == 1
    assert len(report_a.routing_decisions) == 1
    decision = report_a.routing_decisions[0]
    assert isinstance(decision, RoutingMatch), f"expected a RoutingMatch, got {decision!r}"
    assert decision.target_agent == "compliance"
    # the match dispatched exactly one delegation, and it succeeded under the default invoker.
    assert report_a.total_delegations == 1
    assert report_a.delegations[0].status == DelegationStatus.OK

    # workspace audit chain hash-verifies (supervisor's own per-tick F.6 chain).
    assert_audit_chain(ws_a / "audit.jsonl")
    # the dispatcher writes supervisor_report.md (NOT findings.json — it emits no OCSF).
    assert (ws_a / "supervisor_report.md").is_file()
    assert not (ws_a / "findings.json").exists()

    # tenant isolation: a second tenant's tick carries only its own customer_id, writes its own
    # disjoint workspace + audit chain, and shares no trigger identity with tenant_a's report.
    ws_b = tmp_path / "b"
    report_b = await run(
        customer_id="tenant_b",
        workspace_root=ws_b,
        routing_rules=(_rule(),),
        triggers=(_task(customer_id="tenant_b"),),
    )
    assert report_b.customer_id == "tenant_b"
    assert_audit_chain(ws_b / "audit.jsonl")
    # every trigger the supervisor accepted under each tick carries that tick's customer_id.
    assert all(t.customer_id == "tenant_a" for t in report_a.triggers_received)
    assert all(t.customer_id == "tenant_b" for t in report_b.triggers_received)
    # the two ticks are distinct (separate tick ids) — no shared per-tick state across tenants.
    assert report_a.tick_id != report_b.tick_id
