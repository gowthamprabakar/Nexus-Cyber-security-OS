"""supervisor v0.2 Task 9 — F.6 audit vocabulary extension tests (Q4/WI-O5)."""

from __future__ import annotations

from supervisor.audit_emit import (
    ACTION_DELEGATION_COMPLETED,
    ACTION_DELEGATION_DISPATCHED,
    ACTION_DELEGATION_RETRIED,
    ACTION_ESCALATION_RAISED,
    ACTION_HEARTBEAT_STARTED,
    ACTION_PARALLEL_BATCH_STARTED,
    ACTION_QUEUE_DRAINED,
    ACTION_SEMAPHORE_WAIT,
    SUPERVISOR_AUDIT_ACTIONS,
    SUPERVISOR_AUDIT_ACTIONS_V0_1,
    SUPERVISOR_AUDIT_ACTIONS_V0_2,
)


def test_existing_four_byte_identical() -> None:
    """WI-O5: the 4 v0.1 entries are unchanged (exact strings)."""
    assert (
        frozenset(
            {
                "supervisor.heartbeat.started",
                "supervisor.delegation.dispatched",
                "supervisor.delegation.completed",
                "supervisor.escalation.raised",
            }
        )
        == SUPERVISOR_AUDIT_ACTIONS_V0_1
    )


def test_four_new_additive_entries() -> None:
    assert (
        frozenset(
            {
                "supervisor.delegation.parallel_batch_started",
                "supervisor.delegation.retried",
                "supervisor.delegation.semaphore_wait",
                "supervisor.queue.drained",
            }
        )
        == SUPERVISOR_AUDIT_ACTIONS_V0_2
    )


def test_full_set_is_eight() -> None:
    assert len(SUPERVISOR_AUDIT_ACTIONS) == 8


def test_v0_1_and_v0_2_partition_the_full_set() -> None:
    # Additive: the full set is exactly the disjoint union; nothing dropped, nothing renamed.
    assert SUPERVISOR_AUDIT_ACTIONS_V0_1.isdisjoint(SUPERVISOR_AUDIT_ACTIONS_V0_2)
    assert SUPERVISOR_AUDIT_ACTIONS == SUPERVISOR_AUDIT_ACTIONS_V0_1 | SUPERVISOR_AUDIT_ACTIONS_V0_2


def test_new_constants_in_full_set() -> None:
    for action in (
        ACTION_PARALLEL_BATCH_STARTED,
        ACTION_DELEGATION_RETRIED,
        ACTION_SEMAPHORE_WAIT,
        ACTION_QUEUE_DRAINED,
    ):
        assert action in SUPERVISOR_AUDIT_ACTIONS


def test_existing_constants_unchanged() -> None:
    assert ACTION_HEARTBEAT_STARTED == "supervisor.heartbeat.started"
    assert ACTION_DELEGATION_DISPATCHED == "supervisor.delegation.dispatched"
    assert ACTION_DELEGATION_COMPLETED == "supervisor.delegation.completed"
    assert ACTION_ESCALATION_RAISED == "supervisor.escalation.raised"


def test_all_entries_use_supervisor_namespace() -> None:
    assert all(a.startswith("supervisor.") for a in SUPERVISOR_AUDIT_ACTIONS)
