"""Supervisor agent driver — 5-stage pipeline.

Task 10 of the Supervisor v0.1 plan. One fewer stage than A.4 —
Supervisor is stateless in v0.1 (no DELTA stage; no
``previous_scorecards`` fetch from F.5).

Five-stage pipeline:

  1. INGEST     — read triggers: events.> bus (DI-passed) /
                  scheduled queue file / operator-CLI inputs
                  (metadata only — never OCSF body per WI-4).
  2. ROUTE      — pure-function rule engine against agents.md ->
                  RoutingDecision[].
  3. DISPATCH   — parallel dispatch (Semaphore=5); in-process
                  specialist invocation; F.1 budget-enforced;
                  one attempt each.
  4. AUDIT      — F.6 chain entries via audit_emit (heartbeat.started
                  / .dispatched / .completed / .escalation.raised).
  5. HANDOFF    — write supervisor_report.md + per-escalation
                  notification markdown.

**Q5 single-tenant.** ``semantic_store`` defaults to ``None``
(unused in v0.1 — Supervisor is stateless across heartbeats).
Production wires a real instance when the SET LOCAL ``$1``
tenant-RLS substrate-fix lands; v0.1 default exercises the
stateless paths.

**Q-ARCH-1 enforced.** Supervisor never subscribes to ``claims.>``
— Task 8's ``_FORBIDDEN_SUBSCRIPTIONS["supervisor"]`` entry
provides the substrate guard. The driver here doesn't even
import claims surface; smoke test source-grep guard catches any
regression.

**Q-ARCH-2 enforced.** No LLM call anywhere in the routing path.

**Read-only contract (WI-4) preserved.** Workspace markdown +
audit chain are the only write surfaces. No agent NLAH directory
writes.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import ulid
from charter.audit import AuditLog

from supervisor.audit_emit import (
    emit_delegation_completed,
    emit_delegation_dispatched,
    emit_escalation_raised,
    emit_heartbeat_started,
)
from supervisor.dispatch import DelegationInvoker, dispatch_parallel
from supervisor.escalation import (
    build_delegation_escalation,
    build_routing_escalation,
    write_escalation_markdown,
)
from supervisor.routing.router import route
from supervisor.scheduled_queue import drain as drain_scheduled_queue
from supervisor.schemas import (
    MAX_PARALLEL_DISPATCH,
    DelegationContract,
    DelegationOutcome,
    DelegationStatus,
    EscalationNotice,
    IncomingTask,
    RoutingDecision,
    RoutingMatch,
    RoutingRule,
    SupervisorReport,
)

_LOG = logging.getLogger(__name__)

_REPORT_FILENAME = "supervisor_report.md"
_AUDIT_FILENAME = "audit.jsonl"
_DEFAULT_BUDGET_WALL_CLOCK_SEC = 30.0
_DEFAULT_BUDGET_MAX_TOOL_CALLS = 50


def make_logging_invoker() -> DelegationInvoker:
    """v0.1 default invoker — logs the dispatch + no-ops.

    Real fleet specialist invocation lands in Supervisor v0.2
    (production wires this to the actual specialist's
    ``agent.run`` once the cross-agent contract matures). v0.1's
    audit chain proves the dispatch decision; the specialist's
    own machinery handles execution out of band.
    """

    async def _invoke(contract: DelegationContract) -> None:
        _LOG.info(
            "supervisor.dispatch.invoked target_agent=%s delegation_id=%s task_id=%s",
            contract.target_agent,
            contract.delegation_id,
            contract.task_id,
        )

    return _invoke


async def run(
    *,
    customer_id: str,
    workspace_root: Path,
    routing_rules: Sequence[RoutingRule],
    triggers: Sequence[IncomingTask] = (),
    invoker: DelegationInvoker | None = None,
    semantic_store: Any | None = None,
    tick_id: str | None = None,
    concurrency: int = MAX_PARALLEL_DISPATCH,
) -> SupervisorReport:
    """Run the 5-stage Supervisor pipeline for one tick.

    Args:
        customer_id: Tenant identifier (per-customer scoped).
        workspace_root: Root path Supervisor reads from + writes
            ``supervisor_report.md`` and ``escalation_<id>.md`` to.
        routing_rules: Validated rules from ``routing/agents.md``;
            usually loaded by the heartbeat loop at startup.
        triggers: Tasks already collected from events.> + CLI
            sources. The heartbeat loop drains the scheduled
            queue and merges it into this list before calling
            ``run``; tests pass triggers directly.
        invoker: ``DelegationInvoker`` callable. Defaults to
            ``make_logging_invoker()`` for v0.1 (real fleet
            invocation deferred to v0.2).
        semantic_store: Unused in v0.1 (stateless heartbeats).
            Carried in the signature for v0.2 forward-compat.
        tick_id: Heartbeat tick identifier; minted as a ULID if
            omitted.
        concurrency: Per-customer dispatch concurrency cap;
            defaults to ``MAX_PARALLEL_DISPATCH = 5``.

    Returns:
        ``SupervisorReport`` with triggers + decisions + outcomes
        + escalations.
    """
    del semantic_store  # v0.1 placeholder; v0.2 reads F.5 state.

    invoker = invoker or make_logging_invoker()
    workspace_root.mkdir(parents=True, exist_ok=True)
    tick_id_str = tick_id or str(ulid.ULID())
    audit_log = AuditLog(
        workspace_root / _AUDIT_FILENAME,
        agent="supervisor",
        run_id=tick_id_str,
    )

    tick_started_at = datetime.now(UTC)
    triggers_list = list(triggers)
    emit_heartbeat_started(
        audit_log,
        customer_id=customer_id,
        tick_id=tick_id_str,
        triggers=triggers_list,
    )

    # Stage 2 ROUTE — pure-function per trigger.
    decisions = tuple(route(task, routing_rules) for task in triggers_list)

    # Build dispatch contracts only for Match decisions; non-match
    # decisions go to the escalation builder.
    contracts: list[DelegationContract] = []
    contract_to_task: dict[str, IncomingTask] = {}
    contract_to_rule: dict[str, str] = {}
    for task, decision in zip(triggers_list, decisions, strict=True):
        if isinstance(decision, RoutingMatch):
            contract = _build_contract(task=task, match=decision)
            contracts.append(contract)
            contract_to_task[contract.delegation_id] = task
            contract_to_rule[contract.delegation_id] = decision.rule_id

    # Stage 3 DISPATCH — emit dispatched audit entries first, then
    # invoke under Semaphore(concurrency).
    for contract in contracts:
        emit_delegation_dispatched(
            audit_log,
            contract=contract,
            rule_id=contract_to_rule[contract.delegation_id],
        )
    outcomes: tuple[DelegationOutcome, ...] = ()
    if contracts:
        outcomes = tuple(
            await dispatch_parallel(
                contracts,
                invoker=invoker,
                concurrency=concurrency,
            )
        )

    # Stage 4 AUDIT — completed + escalation entries.
    escalations: list[EscalationNotice] = []
    for outcome in outcomes:
        emit_delegation_completed(audit_log, outcome=outcome, customer_id=customer_id)
        if outcome.status != DelegationStatus.OK:
            task = contract_to_task[outcome.delegation_id]
            notice = build_delegation_escalation(
                outcome,
                customer_id=customer_id,
                task_id=task.task_id,
            )
            if notice is not None:
                md_path = write_escalation_markdown(notice, workspace_root=workspace_root)
                emit_escalation_raised(
                    audit_log,
                    notice=notice,
                    escalation_markdown_path=md_path,
                )
                escalations.append(notice)

    # Routing-time escalations (NoMatch / Ambiguous / Escalate).
    for task, decision in zip(triggers_list, decisions, strict=True):
        notice = build_routing_escalation(
            decision,
            customer_id=customer_id,
            task_id=task.task_id,
        )
        if notice is None:
            continue
        md_path = write_escalation_markdown(notice, workspace_root=workspace_root)
        emit_escalation_raised(
            audit_log,
            notice=notice,
            escalation_markdown_path=md_path,
        )
        escalations.append(notice)

    # Stage 5 HANDOFF.
    tick_completed_at = datetime.now(UTC)
    report = SupervisorReport(
        customer_id=customer_id,
        tick_id=tick_id_str,
        tick_started_at=tick_started_at,
        tick_completed_at=tick_completed_at,
        triggers_received=tuple(triggers_list),
        routing_decisions=decisions,
        delegations=outcomes,
        escalations=tuple(escalations),
    )
    _write_supervisor_report_markdown(report, workspace_root=workspace_root)
    return report


def drain_triggers(
    workspace_root: Path,
    *,
    customer_id: str,
    extra: Sequence[IncomingTask] = (),
) -> list[IncomingTask]:
    """Convenience for heartbeat / CLI — drains the file-backed
    scheduled queue and prepends any ``extra`` triggers (e.g.,
    CLI-provided tasks)."""
    queued = drain_scheduled_queue(workspace_root, customer_id=customer_id)
    return list(extra) + queued


def _build_contract(*, task: IncomingTask, match: RoutingMatch) -> DelegationContract:
    return DelegationContract(
        delegation_id=str(ulid.ULID()),
        customer_id=task.customer_id,
        target_agent=match.target_agent,
        task_id=task.task_id,
        task_description=task.description,
        permitted_tools=match.permitted_tools,
        budget_wall_clock_sec=_DEFAULT_BUDGET_WALL_CLOCK_SEC,
        budget_max_tool_calls=_DEFAULT_BUDGET_MAX_TOOL_CALLS,
        created_at=datetime.now(UTC),
    )


def _write_supervisor_report_markdown(
    report: SupervisorReport,
    *,
    workspace_root: Path,
) -> Path:
    path = workspace_root / _REPORT_FILENAME
    parts: list[str] = [
        f"# Supervisor heartbeat report — `{report.customer_id}` / `{report.tick_id}`\n",
        f"- **Tick window:** {report.tick_started_at.isoformat()} -> "
        f"{report.tick_completed_at.isoformat()}\n",
        f"- **Triggers received:** {report.total_triggers}\n",
        f"- **Delegations:** {report.total_delegations} "
        f"({report.successful_delegations} successful)\n",
        f"- **Escalations raised:** {report.total_escalations}\n",
        "",
    ]
    if report.triggers_received:
        parts.append("## Triggers\n")
        for task in report.triggers_received:
            parts.append(
                f"- `{task.task_id}` from `{task.trigger_source.value}` "
                f"-> target_agent=`{task.target_agent}` "
                f"task_type=`{task.task_type}` delta_type=`{task.delta_type}`"
            )
        parts.append("")

    if report.routing_decisions:
        parts.append("## Routing decisions\n")
        for decision in report.routing_decisions:
            parts.append(f"- {_format_decision(decision)}")
        parts.append("")

    if report.delegations:
        parts.append("## Delegation outcomes\n")
        for outcome in report.delegations:
            parts.append(
                f"- `{outcome.delegation_id}` -> `{outcome.target_agent}`: "
                f"{outcome.status.value} ({outcome.duration_sec:.2f}s)"
                + (f" - {outcome.reason}" if outcome.reason else "")
            )
        parts.append("")

    if report.escalations:
        parts.append("## Escalations\n")
        for notice in report.escalations:
            parts.append(f"- `{notice.escalation_id}` (task=`{notice.task_id}`): {notice.reason}")
        parts.append("")

    parts.append("---\n")
    parts.append(f"_Report schema: `{report.schema_version}`._\n")

    path.write_text("\n".join(parts), encoding="utf-8")
    return path


def _format_decision(decision: RoutingDecision) -> str:
    return f"{decision.kind}: {decision.model_dump_json()}"


__all__ = [
    "drain_triggers",
    "make_logging_invoker",
    "run",
]
