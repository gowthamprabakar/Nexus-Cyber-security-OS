"""Audit Agent driver — wires charter + ingest tools + store + summarizer.

F.6 Task 12. Mirrors D.3's [`agent.py`](../../../../runtime-threat/src/runtime_threat/agent.py)
shape — `(contract, *, ...)` signature, `asyncio.TaskGroup` fan-out for
the ingest sources, charter-bounded workspace writes. The one deviation
from D.3 is the **always-on budget exception** (ADR-007 v1.3 candidate):

The Audit Agent honours only `wall_clock_sec` from its `BudgetSpec`.
Every other budget axis (`llm_calls`, `tokens`, `cloud_api_calls`,
`mb_written`) logs a structlog warning when exceeded and proceeds.
F.6 is the first member of this class — the only agent the others
cannot disable, per the glossary.

The always-on policy is locked into the agent driver here (not the
budget envelope itself), so other agents' `consume()` calls keep
their hard stops. The `simulate_budget_overrun_dim` parameter is a
test seam — production callers never set it.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.exceptions import BudgetExhausted
from charter.llm import LLMProvider
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from audit.chain import verify_audit_chain
from audit.schemas import AuditEvent, AuditQueryResult, ChainIntegrityReport
from audit.store import AuditStore
from audit.summarizer import render_markdown
from audit.tools.episode_reader import episode_audit_read
from audit.tools.jsonl_reader import audit_jsonl_read

_LOG = logging.getLogger(__name__)


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to this agent."""
    reg = ToolRegistry()
    reg.register("audit_jsonl_read", audit_jsonl_read, version="0.1.0", cloud_calls=0)
    reg.register("episode_audit_read", episode_audit_read, version="0.1.0", cloud_calls=0)
    return reg


async def run(
    contract: ExecutionContract,
    *,
    audit_store: AuditStore,
    llm_provider: LLMProvider | None = None,
    memory_session_factory: async_sessionmaker[AsyncSession] | None = None,
    sources: Sequence[Path] = (),
    since: datetime | None = None,
    until: datetime | None = None,
    action: str | None = None,
    agent_id: str | None = None,
    correlation_id: str | None = None,
    simulate_budget_overrun_dim: str | None = None,
) -> AuditQueryResult:
    """Ingest audit sources, verify chains, query, render report.

    Args:
        contract: signed `ExecutionContract`.
        audit_store: backing `AuditStore` for ingest + query.
        llm_provider: optional LLMProvider (reserved for future NL-summary use).
        memory_session_factory: optional access to F.5's `episodes` table.
        sources: jsonl filesystem paths emitted by `charter.audit.AuditLog`.
        since / until / action / agent_id / correlation_id: filter axes
            for the final `AuditStore.query` call.
        simulate_budget_overrun_dim: test seam — when set, simulates a
            BudgetExhausted on that dimension to exercise the always-on
            policy. Production callers leave this None.

    Returns:
        The filter-narrowed `AuditQueryResult`. Side effects: writes
        `report.md`, `events.json`, and `audit.jsonl` to the charter
        workspace.
    """
    del llm_provider  # reserved for future NL-summary work; not load-bearing in v0.1
    tenant_id = contract.customer_id
    registry = build_registry()

    with Charter(contract, tools=registry) as ctx:
        if simulate_budget_overrun_dim is not None:
            _simulate_budget_overrun(ctx, dimension=simulate_budget_overrun_dim)

        jsonl_events, memory_events = await _fetch_sources(
            tenant_id=tenant_id,
            sources=sources,
            memory_session_factory=memory_session_factory,
        )

        chain_report = _verify_chains(jsonl_events=jsonl_events, memory_events=memory_events)

        combined = jsonl_events + memory_events
        if combined:
            await audit_store.ingest(tenant_id=tenant_id, events=combined)

        result = await audit_store.query(
            tenant_id=tenant_id,
            since=since,
            until=until,
            action=action,
            agent_id=agent_id,
            correlation_id=correlation_id,
        )

        report_window_since = since or datetime(2020, 1, 1, tzinfo=UTC)
        report_window_until = until or datetime.now(UTC)
        report = render_markdown(
            tenant_id=tenant_id,
            since=report_window_since,
            until=report_window_until,
            result=result,
            chain=chain_report,
        )

        ctx.write_output("report.md", report.encode("utf-8"))
        ctx.write_output("events.json", result.model_dump_json(indent=2).encode("utf-8"))
        ctx.assert_complete()

    return result


# ---------------------------- internals ---------------------------------


def _simulate_budget_overrun(ctx: Charter, *, dimension: str) -> None:
    """Test seam: trigger BudgetExhausted on the given dimension.

    For non-wall-clock dimensions, the always-on policy below catches +
    logs the warning. For `wall_clock_sec`, the exception propagates.
    """
    try:
        if dimension == "wall_clock_sec":
            raise BudgetExhausted(
                dimension="wall_clock_sec",
                limit=ctx.budget.wall_clock_sec,
                used=ctx.budget.wall_clock_sec + 1,
            )
        raise BudgetExhausted(
            dimension=dimension,
            limit=float(getattr(ctx.budget, dimension)),
            used=float(getattr(ctx.budget, dimension)) + 1,
        )
    except BudgetExhausted as exc:
        _enforce_always_on(exc)


def _enforce_always_on(exc: BudgetExhausted) -> None:
    """ADR-007 v1.3 always-on policy: re-raise only on wall_clock_sec.

    Every other budget axis logs a warning and proceeds. The Audit
    Agent is the only agent allowed to do this; future always-on
    agents go through the same helper.
    """
    if exc.dimension == "wall_clock_sec":
        raise exc
    _LOG.warning(
        "audit-agent always-on: budget axis %s exhausted (limit=%s, used=%s); proceeding",
        exc.dimension,
        exc.limit,
        exc.used,
    )


async def _fetch_sources(
    *,
    tenant_id: str,
    sources: Sequence[Path],
    memory_session_factory: async_sessionmaker[AsyncSession] | None,
) -> tuple[tuple[AuditEvent, ...], tuple[AuditEvent, ...]]:
    """Fan out the ingest tools concurrently via `asyncio.TaskGroup`.

    jsonl sources read in parallel; the memory read fires alongside.
    """
    jsonl_results: list[tuple[AuditEvent, ...]] = []
    memory_result: tuple[AuditEvent, ...] = ()

    async with asyncio.TaskGroup() as tg:
        jsonl_tasks = [
            tg.create_task(audit_jsonl_read(path=src, tenant_id=tenant_id)) for src in sources
        ]
        memory_task = (
            tg.create_task(
                episode_audit_read(session_factory=memory_session_factory, tenant_id=tenant_id)
            )
            if memory_session_factory is not None
            else None
        )

    for task in jsonl_tasks:
        jsonl_results.append(task.result())
    if memory_task is not None:
        memory_result = memory_task.result()

    flat_jsonl: tuple[AuditEvent, ...] = tuple(event for batch in jsonl_results for event in batch)
    return flat_jsonl, memory_result


def _verify_chains(
    *,
    jsonl_events: tuple[AuditEvent, ...],
    memory_events: tuple[AuditEvent, ...],
) -> ChainIntegrityReport:
    """Verify both source kinds. Merge into one report.

    If either source breaks, the merged report is invalid and surfaces
    the first break. jsonl events go through `sequential=True`; memory
    events through `sequential=False` (per F.6 Task 8's mode split).
    """
    jsonl_report = verify_audit_chain(jsonl_events, sequential=True)
    if not jsonl_report.valid:
        return jsonl_report
    memory_report = verify_audit_chain(memory_events, sequential=False)
    if not memory_report.valid:
        return memory_report
    return ChainIntegrityReport(
        valid=True,
        entries_checked=jsonl_report.entries_checked + memory_report.entries_checked,
        broken_at_correlation_id=None,
        broken_at_action=None,
    )


__all__ = ["build_registry", "run"]
