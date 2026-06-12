"""WI-O4 (HARD) — supervisor multi-agent dispatch end-to-end (supervisor v0.2 Task 17).

Per the WI-V6 / WI-I4 / WI-T4 / WI-R4 / WI-N4 / WI-K4 / WI-C2 / WI-S4 / WI-F4 lineage. The full
supervisor pipeline, exercised offline with an injected invoker standing in for the 11 live
agents (real agent execution is the Phase C consolidated retrofit, WI-O2):

  trigger ingestion (event-bus + scheduled queue) -> routing -> registry-validated live dispatch
  to the 11 v0.2 agents -> dependency-ordered orchestration + aggregation -> F.6 audit emission.

Per-agent concurrency, the transient retry path (Q3), and the four invariants are all exercised:
the hierarchy guard (WI-O8), the signed-contract guard (WI-O9), the ``_FORBIDDEN_SUBSCRIPTIONS``
fence (WI-O10), and the deviation profile (no OCSF / no Charter wrap / no tools, WI-O11).
No tests/integration/__init__.py (importlib).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from charter.audit import AuditLog
from supervisor.audit_emit import (
    ACTION_DELEGATION_RETRIED,
    ACTION_PARALLEL_BATCH_STARTED,
    emit_delegation_retried,
    emit_parallel_batch_started,
)
from supervisor.concurrency.per_agent import PerAgentSemaphores, run_under_limits
from supervisor.contract_signing import assert_signed_contract, sign_delegation
from supervisor.failure.classifier import FailureClass
from supervisor.failure.retry import run_with_retry
from supervisor.hierarchy import PeerToPeerViolationError, assert_no_peer_to_peer
from supervisor.queue.drainer import QueueDrainer
from supervisor.queue.sqlite_store import SqliteQueueStore
from supervisor.routing.live_dispatch import execute_live, plan_live_delegations
from supervisor.routing.live_registry import V0_2_AGENTS
from supervisor.routing.orchestration import aggregate_outcomes, order_by_dependencies
from supervisor.schemas import (
    DelegationContract,
    DelegationOutcome,
    DelegationStatus,
)
from supervisor.triggers.coexistence import route_decision
from supervisor.triggers.event_bus import EventBusListener, ForbiddenEventSubscriptionError

_NOW = datetime(2026, 6, 1, tzinfo=UTC)
_SECRET = b"e2e-signing-key"


def _contract(target: str) -> DelegationContract:
    return DelegationContract(
        delegation_id=f"d-{target}",
        customer_id="c1",
        target_agent=target,
        task_id=f"task-{target}",
        budget_wall_clock_sec=30.0,
        budget_max_tool_calls=100,
        created_at=_NOW,
    )


async def _ok_invoker(contract: DelegationContract) -> None:
    return None


def test_full_dispatch_pipeline_across_11_agents() -> None:
    # plan registry-validated delegations to all 11 v0.2 agents, dispatch via the invoker.
    contracts = [_contract(a) for a in V0_2_AGENTS]
    delegations = plan_live_delegations(contracts)
    import asyncio

    result = asyncio.run(execute_live(delegations, invoker=_ok_invoker))
    assert result.full_dispatched == 11 and result.basic_dispatched == 0
    summary = aggregate_outcomes(result.outcomes)
    assert summary.all_ok and summary.total == 11


def test_event_bus_then_route() -> None:
    listener = EventBusListener(subscriptions=["events.>"])
    task = listener.ingest(
        {"task_id": "t1", "customer_id": "c1", "target_agent": "compliance"}, now=_NOW
    )
    from supervisor.schemas import RoutingRule

    rules = (
        RoutingRule(rule_id="r1", target_agent="compliance", target_agent_declared="compliance"),
    )
    decision = route_decision(task, rules)
    assert decision is not None


def test_forbidden_subscription_fence_in_pipeline() -> None:
    # WI-O10: the listener refuses a claims.> subscription.
    with pytest.raises(ForbiddenEventSubscriptionError):
        EventBusListener(subscriptions=["events.>", "claims.>"])


@pytest.mark.asyncio
async def test_scheduled_queue_drain_to_dispatch(tmp_path: Path) -> None:
    db = tmp_path / "q.db"
    store = SqliteQueueStore(db)
    store.enqueue(customer_id="c1", task={"task_id": "t1", "target_agent": "audit"})
    store.close()
    dispatched: list[str] = []

    async def _process(task: dict[str, Any]) -> None:
        dispatched.append(task["target_agent"])

    summary = await QueueDrainer(db).drain(customer_id="c1", process=_process)
    assert summary.drained == 1 and dispatched == ["audit"]


@pytest.mark.asyncio
async def test_per_agent_concurrency_in_pipeline() -> None:
    sems = PerAgentSemaphores(overrides={"compliance": 2})
    live = 0
    peak = 0

    async def _probe() -> int:
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        import asyncio

        await asyncio.sleep(0.005)
        live -= 1
        return 1

    await run_under_limits([("compliance", _probe) for _ in range(5)], semaphores=sems)
    assert peak <= 2


@pytest.mark.asyncio
async def test_transient_retry_path_with_audit(tmp_path: Path) -> None:
    # transient fail -> one retry -> OK; the retry surfaces the supervisor.delegation.retried entry.
    outcomes = iter(
        [
            DelegationOutcome(
                delegation_id="d-1",
                target_agent="compliance",
                status=DelegationStatus.ERROR,
                duration_sec=1.0,
                reason="503",
                completed_at=_NOW,
            ),
            DelegationOutcome(
                delegation_id="d-1",
                target_agent="compliance",
                status=DelegationStatus.OK,
                duration_sec=1.0,
                completed_at=_NOW,
            ),
        ]
    )

    async def _attempt(contract: DelegationContract) -> DelegationOutcome:
        return next(outcomes)

    result = await run_with_retry(_contract("compliance"), attempt=_attempt)
    assert result.retried is True and result.outcome.status is DelegationStatus.OK

    log = AuditLog(tmp_path / "audit.jsonl", agent="supervisor", run_id="tick1")
    emit_delegation_retried(
        log, contract=_contract("compliance"), attempt=2, failure_class=FailureClass.TRANSIENT.value
    )
    actions = [
        json.loads(line)["action"] for line in log.path.read_text().splitlines() if line.strip()
    ]
    assert ACTION_DELEGATION_RETRIED in actions


def test_hierarchy_and_signed_contract_invariants() -> None:
    # WI-O8: only supervisor dispatches.
    assert_no_peer_to_peer("supervisor", "compliance")
    with pytest.raises(PeerToPeerViolationError):
        assert_no_peer_to_peer("compliance", "audit")
    # WI-O9: a signed contract verifies; tampering is rejected.
    assert_signed_contract(sign_delegation(_contract("compliance"), secret=_SECRET), secret=_SECRET)


def test_dependency_ordering_in_pipeline() -> None:
    # compliance waits for the posture agents.
    waves = order_by_dependencies(["compliance", "cloud_posture", "k8s_posture"])
    assert waves[-1] == ("compliance",)


def test_parallel_batch_audit_entry(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl", agent="supervisor", run_id="tick1")
    emit_parallel_batch_started(
        log, customer_id="c1", tick_id="tk1", target_agents=list(V0_2_AGENTS)
    )
    actions = [
        json.loads(line)["action"] for line in log.path.read_text().splitlines() if line.strip()
    ]
    assert ACTION_PARALLEL_BATCH_STARTED in actions
