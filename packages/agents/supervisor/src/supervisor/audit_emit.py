"""F.6 audit-chain emitters — Stage 4 AUDIT helpers.

Per Q6: 4 additive audit-action vocabulary entries (per
[ADR-010](../../../../docs/_meta/decisions/ADR-010-within-agent-version-extension.md)
condition 4 — additive-only; no existing strings touched):

- ``supervisor.heartbeat.started`` — every heartbeat tick start;
  carries ``customer_id`` + ``tick_id`` + trigger-source counts.
- ``supervisor.delegation.dispatched`` — one per delegation;
  carries ``target_agent`` + ``delegation_id`` + ``rule_id``.
- ``supervisor.delegation.completed`` — one per delegation; carries
  ``status`` + ``duration_sec`` + ``reason`` (if non-OK).
- ``supervisor.escalation.raised`` — one per escalation; carries
  ``reason`` + escalation markdown path.

F.6 hash-chain semantics inherited unchanged from ``charter.audit``.
The driver (Task 10) constructs ONE ``AuditLog`` per heartbeat
tick (per Q-ARCH discipline — one audit file per run) and threads
these helpers around the pipeline.

**Write-only (Q5).** Supervisor v0.1 does NOT read the audit
chain for decision-making. These helpers are side-effect-only.

**No bus emission.** Audit entries land in the hash-chained file;
no fabric publish.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from charter.audit import AuditLog

from supervisor.schemas import (
    DelegationContract,
    DelegationOutcome,
    EscalationNotice,
    IncomingTask,
)

# The 4 additive audit-action vocabulary entries — used by the
# driver + asserted by Task 9's tests + Task 12's eval cases.
ACTION_HEARTBEAT_STARTED = "supervisor.heartbeat.started"
ACTION_DELEGATION_DISPATCHED = "supervisor.delegation.dispatched"
ACTION_DELEGATION_COMPLETED = "supervisor.delegation.completed"
ACTION_ESCALATION_RAISED = "supervisor.escalation.raised"

# v0.2 Task 9 — 4 ADDITIVE vocabulary entries (Q4 / WI-O5). The 4 existing entries above stay
# byte-identical; these are appended and never modify the existing schema. Emission wiring
# lands in Task 10.
ACTION_PARALLEL_BATCH_STARTED = "supervisor.delegation.parallel_batch_started"
ACTION_DELEGATION_RETRIED = "supervisor.delegation.retried"
ACTION_SEMAPHORE_WAIT = "supervisor.delegation.semaphore_wait"
ACTION_QUEUE_DRAINED = "supervisor.queue.drained"


def emit_heartbeat_started(
    audit_log: AuditLog,
    *,
    customer_id: str,
    tick_id: str,
    triggers: Sequence[IncomingTask],
) -> None:
    """Emit the per-tick start entry."""
    source_counts = _count_triggers_by_source(triggers)
    payload: dict[str, Any] = {
        "customer_id": customer_id,
        "tick_id": tick_id,
        "trigger_count_total": len(triggers),
        "triggers_by_source": source_counts,
    }
    audit_log.append(ACTION_HEARTBEAT_STARTED, payload)


def emit_delegation_dispatched(
    audit_log: AuditLog,
    *,
    contract: DelegationContract,
    rule_id: str,
) -> None:
    """Emit one entry per delegation at dispatch time."""
    payload: dict[str, Any] = {
        "customer_id": contract.customer_id,
        "delegation_id": contract.delegation_id,
        "target_agent": contract.target_agent,
        "task_id": contract.task_id,
        "rule_id": rule_id,
        "budget_wall_clock_sec": contract.budget_wall_clock_sec,
        "budget_max_tool_calls": contract.budget_max_tool_calls,
    }
    audit_log.append(ACTION_DELEGATION_DISPATCHED, payload)


def emit_delegation_completed(
    audit_log: AuditLog,
    *,
    outcome: DelegationOutcome,
    customer_id: str,
) -> None:
    """Emit one entry per delegation at completion time."""
    payload: dict[str, Any] = {
        "customer_id": customer_id,
        "delegation_id": outcome.delegation_id,
        "target_agent": outcome.target_agent,
        "status": outcome.status.value,
        "duration_sec": outcome.duration_sec,
        "completed_at": outcome.completed_at.isoformat(),
    }
    if outcome.reason is not None:
        payload["reason"] = outcome.reason
    audit_log.append(ACTION_DELEGATION_COMPLETED, payload)


def emit_escalation_raised(
    audit_log: AuditLog,
    *,
    notice: EscalationNotice,
    escalation_markdown_path: Path | None,
) -> None:
    """Emit one entry per escalation."""
    payload: dict[str, Any] = {
        "customer_id": notice.customer_id,
        "escalation_id": notice.escalation_id,
        "task_id": notice.task_id,
        "reason": notice.reason,
        "raised_at": notice.raised_at.isoformat(),
    }
    if escalation_markdown_path is not None:
        payload["escalation_markdown"] = str(escalation_markdown_path)
    audit_log.append(ACTION_ESCALATION_RAISED, payload)


def _count_triggers_by_source(triggers: Sequence[IncomingTask]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for trigger in triggers:
        counts[trigger.trigger_source.value] += 1
    return dict(counts)


# --- v0.2 Task 10: emission for the 4 additive vocabulary entries (Q4). Same append-only
# F.6 hash-chain semantics as the v0.1 emitters — these add NEW entries, never edit existing. ---


def emit_parallel_batch_started(
    audit_log: AuditLog,
    *,
    customer_id: str,
    tick_id: str,
    target_agents: Sequence[str],
) -> None:
    """Emit once when a parallel delegation batch begins."""
    payload: dict[str, Any] = {
        "customer_id": customer_id,
        "tick_id": tick_id,
        "batch_size": len(target_agents),
        "target_agents": list(target_agents),
    }
    audit_log.append(ACTION_PARALLEL_BATCH_STARTED, payload)


def emit_delegation_retried(
    audit_log: AuditLog,
    *,
    contract: DelegationContract,
    attempt: int,
    failure_class: str,
) -> None:
    """Emit when a transient failure triggers the single bounded retry (Q3/H4)."""
    payload: dict[str, Any] = {
        "customer_id": contract.customer_id,
        "delegation_id": contract.delegation_id,
        "target_agent": contract.target_agent,
        "attempt": attempt,
        "failure_class": failure_class,
    }
    audit_log.append(ACTION_DELEGATION_RETRIED, payload)


def emit_semaphore_wait(
    audit_log: AuditLog,
    *,
    customer_id: str,
    target_agent: str,
    waited_sec: float,
    cap: int,
) -> None:
    """Emit when a delegation waits on its per-agent concurrency slot (backpressure)."""
    payload: dict[str, Any] = {
        "customer_id": customer_id,
        "target_agent": target_agent,
        "waited_sec": waited_sec,
        "cap": cap,
    }
    audit_log.append(ACTION_SEMAPHORE_WAIT, payload)


def emit_queue_drained(
    audit_log: AuditLog,
    *,
    customer_id: str,
    drained_count: int,
    queue_name: str,
) -> None:
    """Emit when the scheduled queue finishes draining its due items."""
    payload: dict[str, Any] = {
        "customer_id": customer_id,
        "drained_count": drained_count,
        "queue_name": queue_name,
    }
    audit_log.append(ACTION_QUEUE_DRAINED, payload)


# The original v0.1 vocabulary (4) — surfaced separately so tests can assert it stays
# byte-identical under the v0.2 extension (WI-O5).
SUPERVISOR_AUDIT_ACTIONS_V0_1: frozenset[str] = frozenset(
    {
        ACTION_HEARTBEAT_STARTED,
        ACTION_DELEGATION_DISPATCHED,
        ACTION_DELEGATION_COMPLETED,
        ACTION_ESCALATION_RAISED,
    }
)

# The 4 ADDITIVE v0.2 entries (Q4).
SUPERVISOR_AUDIT_ACTIONS_V0_2: frozenset[str] = frozenset(
    {
        ACTION_PARALLEL_BATCH_STARTED,
        ACTION_DELEGATION_RETRIED,
        ACTION_SEMAPHORE_WAIT,
        ACTION_QUEUE_DRAINED,
    }
)

# The full canonical set (8) — the v0.1 set plus the v0.2 additions.
SUPERVISOR_AUDIT_ACTIONS: frozenset[str] = (
    SUPERVISOR_AUDIT_ACTIONS_V0_1 | SUPERVISOR_AUDIT_ACTIONS_V0_2
)


__all__ = [
    "ACTION_DELEGATION_COMPLETED",
    "ACTION_DELEGATION_DISPATCHED",
    "ACTION_DELEGATION_RETRIED",
    "ACTION_ESCALATION_RAISED",
    "ACTION_HEARTBEAT_STARTED",
    "ACTION_PARALLEL_BATCH_STARTED",
    "ACTION_QUEUE_DRAINED",
    "ACTION_SEMAPHORE_WAIT",
    "SUPERVISOR_AUDIT_ACTIONS",
    "SUPERVISOR_AUDIT_ACTIONS_V0_1",
    "SUPERVISOR_AUDIT_ACTIONS_V0_2",
    "emit_delegation_completed",
    "emit_delegation_dispatched",
    "emit_delegation_retried",
    "emit_escalation_raised",
    "emit_heartbeat_started",
    "emit_parallel_batch_started",
    "emit_queue_drained",
    "emit_semaphore_wait",
]
