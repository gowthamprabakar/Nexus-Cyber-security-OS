"""Escalation helpers — Q4 "notify human, do not retry" path.

Two triggers (per plan Q4):

1. Rule-engine terminal: ``RoutingNoMatch`` / ``RoutingAmbiguous``
   / ``RoutingEscalate``. Supervisor records the routing failure
   + raises an escalation.
2. Per-delegation outcome: ``status=TIMEOUT_PARTIAL`` or
   ``status=ERROR``. Supervisor accepts the partial / failed
   outcome + raises an escalation.

Both paths produce:

- An ``EscalationNotice`` pydantic instance (returned by the
  builder for the driver to attach to ``SupervisorReport`` +
  for ``audit_emit.py`` to write the
  ``supervisor.escalation.raised`` audit entry — Task 9).
- A workspace markdown artefact at
  ``<workspace_root>/escalation_<escalation_id>.md`` (operator-
  facing notification; **NOT a fabric publish**).

**No auto-retry.** Re-triggering the failed task is the operator's
job in v0.1.

**Read-only against speculation.** No ``claims.>`` read; no LLM
call; no A.4 introspection. Q-ARCH-1/2/4 + WI-6 carry-forward.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import ulid

from supervisor.schemas import (
    DelegationOutcome,
    DelegationStatus,
    EscalationNotice,
    RoutingAmbiguous,
    RoutingDecision,
    RoutingEscalate,
    RoutingNoMatch,
)


def build_routing_escalation(
    decision: RoutingDecision,
    *,
    customer_id: str,
    task_id: str,
) -> EscalationNotice | None:
    """Build an EscalationNotice for a non-Match RoutingDecision.

    Returns ``None`` for ``RoutingMatch`` (the dispatch path
    handles those). Returns a fresh ``EscalationNotice`` for
    ``NoMatch`` / ``Ambiguous`` / ``Escalate`` variants.
    """
    if isinstance(decision, RoutingNoMatch | RoutingAmbiguous | RoutingEscalate):
        return EscalationNotice(
            escalation_id=str(ulid.ULID()),
            customer_id=customer_id,
            task_id=task_id,
            reason=decision.reason,
            raised_at=datetime.now(UTC),
        )
    return None


def build_delegation_escalation(
    outcome: DelegationOutcome,
    *,
    customer_id: str,
    task_id: str,
) -> EscalationNotice | None:
    """Build an EscalationNotice for a non-OK DelegationOutcome.

    Returns ``None`` for ``status=OK``. Returns a fresh
    ``EscalationNotice`` for ``TIMEOUT_PARTIAL`` / ``ERROR``.
    """
    if outcome.status == DelegationStatus.OK:
        return None
    reason = outcome.reason or f"delegation status={outcome.status.value}"
    return EscalationNotice(
        escalation_id=str(ulid.ULID()),
        customer_id=customer_id,
        task_id=task_id,
        reason=f"{outcome.target_agent}: {reason}",
        raised_at=datetime.now(UTC),
    )


def write_escalation_markdown(
    notice: EscalationNotice,
    *,
    workspace_root: Path,
) -> Path:
    """Write the operator-facing escalation markdown.

    Output path: ``<workspace_root>/escalation_<escalation_id>.md``.

    The markdown is the operator's notification artefact — paired
    with the ``supervisor.escalation.raised`` audit entry (Task 9).
    NOT a fabric publish (Q-ARCH-2 fence).
    """
    workspace_root.mkdir(parents=True, exist_ok=True)
    path = workspace_root / f"escalation_{notice.escalation_id}.md"
    body = _render_markdown(notice)
    path.write_text(body, encoding="utf-8")
    return path


def _render_markdown(notice: EscalationNotice) -> str:
    return (
        f"# Supervisor escalation — `{notice.escalation_id}`\n\n"
        f"- **Customer:** `{notice.customer_id}`\n"
        f"- **Task:** `{notice.task_id}`\n"
        f"- **Raised at:** {notice.raised_at.isoformat()}\n\n"
        f"## Reason\n\n"
        f"{notice.reason}\n\n"
        f"---\n\n"
        f"_This escalation is operator-facing only — Supervisor v0.1 does not "
        f"auto-retry. Re-triggering the failed task is the operator's "
        f"responsibility._\n"
    )


__all__ = [
    "build_delegation_escalation",
    "build_routing_escalation",
    "write_escalation_markdown",
]
