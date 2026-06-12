"""supervisor v0.2 Task 4 — multi-agent dispatch orchestration tests (Q1)."""

from __future__ import annotations

from datetime import UTC, datetime

from supervisor.routing.orchestration import (
    aggregate_outcomes,
    order_by_dependencies,
)
from supervisor.schemas import DelegationOutcome, DelegationStatus


def _outcome(
    agent: str, status: DelegationStatus, *, reason: str | None = None
) -> DelegationOutcome:
    if status is not DelegationStatus.OK and reason is None:
        reason = "x"
    return DelegationOutcome(
        delegation_id=f"d-{agent}",
        target_agent=agent,
        status=status,
        duration_sec=1.0,
        reason=reason,
        completed_at=datetime(2026, 6, 1, tzinfo=UTC),
    )


def test_no_deps_single_wave() -> None:
    waves = order_by_dependencies(["audit", "identity"])
    assert waves == [("audit", "identity")]


def test_compliance_after_posture() -> None:
    waves = order_by_dependencies(["compliance", "cloud_posture", "k8s_posture"])
    # posture agents first, compliance in a later wave.
    assert "compliance" not in waves[0]
    assert waves[-1] == ("compliance",)
    assert {"cloud_posture", "k8s_posture"} <= set(waves[0])


def test_absent_dependency_does_not_block() -> None:
    # compliance's posture deps aren't in scope -> compliance dispatches immediately.
    waves = order_by_dependencies(["compliance", "audit"])
    assert waves == [("compliance", "audit")]


def test_dedup_preserves_order() -> None:
    waves = order_by_dependencies(["audit", "audit", "identity"])
    assert waves == [("audit", "identity")]


def test_partial_deps_in_scope() -> None:
    # only cloud_posture in scope -> compliance waits just for it.
    waves = order_by_dependencies(["compliance", "cloud_posture"])
    assert waves[0] == ("cloud_posture",) and waves[1] == ("compliance",)


def test_aggregate_counts() -> None:
    outcomes = [
        _outcome("a", DelegationStatus.OK),
        _outcome("b", DelegationStatus.ERROR),
        _outcome("c", DelegationStatus.TIMEOUT_PARTIAL),
    ]
    summary = aggregate_outcomes(outcomes)
    assert summary.total == 3 and summary.ok == 1 and summary.error == 1 and summary.timeout == 1
    assert summary.all_ok is False


def test_aggregate_by_agent() -> None:
    summary = aggregate_outcomes([_outcome("audit", DelegationStatus.OK)])
    assert summary.by_agent == {"audit": "ok"} and summary.all_ok is True


def test_aggregate_empty() -> None:
    summary = aggregate_outcomes([])
    assert summary.total == 0 and summary.all_ok is False


def test_empty_targets() -> None:
    assert order_by_dependencies([]) == []
