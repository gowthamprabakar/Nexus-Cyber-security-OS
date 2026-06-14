"""Supervisor Agent CLI — 4 subcommands (per plan Task 13).

- ``supervisor eval [CASES_DIR]`` — run the local meta-eval suite
  via the eval-framework's ``run_suite`` against the registered
  ``SupervisorEvalRunner``. Exits 0 on 15/15; non-zero on any
  failure.

- ``supervisor heartbeat-once --customer-id ID [...]`` — one-shot
  tick. Optionally injects a single operator-CLI task via
  ``--task-id / --target-agent / --task-type / --delta-type``.
  Prints the per-tick digest + report path.

- ``supervisor schedule --customer-id ID --task-id ID [...]`` —
  enqueue one task to the file-backed scheduled-queue. The next
  heartbeat tick drains it.

- ``supervisor run --customer-id ID [--tick-interval-seconds 60
  --max-ticks N]`` — start the heartbeat loop. Long-running by
  default; ``--max-ticks`` bounds it for tests + smoke runs.

**Read-only against speculation.** No subcommand subscribes to
``claims.>`` — Q-ARCH-1 substrate fence keyed by agent_id="supervisor".
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import click
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite
from nexus_runtime import ContinuousDriver

from supervisor import __version__
from supervisor.agent import run as agent_run
from supervisor.cadence import resolve_cadence
from supervisor.continuous_source import ContinuousTriggerSource
from supervisor.eval_runner import SupervisorEvalRunner
from supervisor.heartbeat import (
    DEFAULT_TICK_INTERVAL_SECONDS,
    Heartbeat,
)
from supervisor.routing.parser import load_routing_rules
from supervisor.scheduled_queue import enqueue as enqueue_scheduled
from supervisor.schemas import IncomingTask, TriggerSource

_LOG = logging.getLogger(__name__)
_DEFAULT_CASES_DIR = Path(__file__).parent.parent.parent / "eval" / "cases"
_DEFAULT_AGENTS_MD = Path(__file__).parent / "routing" / "agents.md"


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Supervisor Agent — declarative router + parallel dispatcher + heartbeat orchestrator."""


# ---------------------- eval --------------------------------------------


@main.command("eval")
@click.argument(
    "cases_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=False,
)
def eval_cmd(cases_dir: Path | None) -> None:
    """Run the local meta-eval suite (15 routing-test cases by default)."""
    target = cases_dir or _DEFAULT_CASES_DIR
    if not target.is_dir():
        click.echo(f"ERROR: cases dir not found: {target}", err=True)
        raise SystemExit(2)
    cases = load_cases(target)
    suite = asyncio.run(run_suite(cases, SupervisorEvalRunner()))
    passed = sum(1 for r in suite.cases if r.passed)
    total = len(suite.cases)
    click.echo(f"{passed}/{total} passed")
    failures = [r for r in suite.cases if not r.passed]
    for r in failures:
        click.echo(f"  FAIL {r.case_id}: {r.failure_reason}", err=True)
        if r.actuals:
            click.echo(f"    actuals: {r.actuals}", err=True)
    if failures:
        raise SystemExit(1)


# ---------------------- heartbeat-once ----------------------------------


@main.command("heartbeat-once")
@click.option("--customer-id", required=True, help="Tenant identifier")
@click.option(
    "--workspace-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path.cwd(),
    show_default=True,
)
@click.option("--task-id", help="Inject one operator-CLI task with this id")
@click.option("--target-agent", help="Target agent for the injected task")
@click.option("--task-type", help="task_type for the injected task")
@click.option("--delta-type", help="delta_type for the injected task")
@click.option("--task-description", default="", show_default=True)
@click.option(
    "--agents-md",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=_DEFAULT_AGENTS_MD,
    show_default=True,
    help="Routing-table file",
)
def heartbeat_once_cmd(
    customer_id: str,
    workspace_root: Path,
    task_id: str | None,
    target_agent: str | None,
    task_type: str | None,
    delta_type: str | None,
    task_description: str,
    agents_md: Path,
) -> None:
    """Run a single heartbeat tick (drains scheduled queue + optionally
    injects one operator-CLI task)."""
    workspace_root.mkdir(parents=True, exist_ok=True)
    rules = load_routing_rules(agents_md)

    extra: list[IncomingTask] = []
    if task_id:
        if not (target_agent or task_type or delta_type):
            click.echo(
                "ERROR: --task-id requires at least one of "
                "--target-agent / --task-type / --delta-type",
                err=True,
            )
            raise SystemExit(2)
        extra.append(
            IncomingTask(
                task_id=task_id,
                customer_id=customer_id,
                trigger_source=TriggerSource.OPERATOR_CLI,
                target_agent=target_agent,
                task_type=task_type,
                delta_type=delta_type,
                description=task_description,
                received_at=datetime.now(UTC),
            )
        )

    from supervisor.scheduled_queue import drain as drain_scheduled_queue

    queued = drain_scheduled_queue(workspace_root, customer_id=customer_id)
    triggers = extra + queued

    report = asyncio.run(
        agent_run(
            customer_id=customer_id,
            workspace_root=workspace_root,
            routing_rules=rules,
            triggers=triggers,
        )
    )
    click.echo(
        f"tick={report.tick_id} triggers={report.total_triggers} "
        f"delegations={report.total_delegations} "
        f"({report.successful_delegations} successful) "
        f"escalations={report.total_escalations}"
    )
    click.echo(f"report: {workspace_root / 'supervisor_report.md'}")


# ---------------------- schedule -----------------------------------------


@main.command("schedule")
@click.option("--customer-id", required=True)
@click.option("--task-id", required=True)
@click.option("--target-agent")
@click.option("--task-type")
@click.option("--delta-type")
@click.option("--description", default="", show_default=True)
@click.option(
    "--priority",
    type=click.IntRange(0, 10),
    default=0,
    show_default=True,
)
@click.option(
    "--workspace-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path.cwd(),
    show_default=True,
)
def schedule_cmd(
    customer_id: str,
    task_id: str,
    target_agent: str | None,
    task_type: str | None,
    delta_type: str | None,
    description: str,
    priority: int,
    workspace_root: Path,
) -> None:
    """Enqueue one task to the file-backed scheduled queue."""
    if not (target_agent or task_type or delta_type):
        click.echo(
            "ERROR: schedule requires at least one of --target-agent / --task-type / --delta-type",
            err=True,
        )
        raise SystemExit(2)

    task: dict[str, object] = {
        "task_id": task_id,
        "customer_id": customer_id,
        "description": description,
        "priority": priority,
    }
    if target_agent:
        task["target_agent"] = target_agent
    if task_type:
        task["task_type"] = task_type
    if delta_type:
        task["delta_type"] = delta_type

    enqueue_scheduled(workspace_root, customer_id=customer_id, task=task)
    click.echo(f"enqueued {task_id} for {customer_id}")


# ---------------------- run (long-running loop) --------------------------


def _resolve_continuous_source(
    *, continuous_mode: bool, continuous_kill_switch: bool
) -> tuple[ContinuousTriggerSource | None, dict[str, bool]]:
    """Track D D-1: resolve the continuous trigger source for a ``run``.

    Default OFF → ``None`` (Heartbeat falls back to its no-op continuous source =
    heartbeat-only, byte-identical to pre-Track-D behaviour). When continuous mode
    is requested AND not kill-switched for this tenant, build a
    ``ContinuousTriggerSource`` over an empty ``ContinuousDriver`` — **wired but
    inert** (no schedulers registered → no due runs), per Q3 "wire + OFF, NOT
    activation". The per-tenant kill-switch overrides the global enable.

    Returns ``(source_or_None, decision)`` where ``decision`` is the audit/
    observability record of how the effective state was resolved.
    """
    effective = continuous_mode and not continuous_kill_switch
    decision = {
        "continuous_mode_requested": continuous_mode,
        "continuous_kill_switch": continuous_kill_switch,
        "continuous_effective": effective,
    }
    if not effective:
        return None, decision
    # Empty driver: wired into the tick path but produces no due runs until a
    # future cycle registers schedulers. This is the "wire, not activate" state.
    return ContinuousTriggerSource(ContinuousDriver()), decision


@main.command("run")
@click.option("--customer-id", required=True)
@click.option(
    "--workspace-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path.cwd(),
    show_default=True,
)
@click.option(
    "--tick-interval-seconds",
    type=click.FloatRange(min=0.0, min_open=True),
    default=DEFAULT_TICK_INTERVAL_SECONDS,
    show_default=True,
)
@click.option(
    "--max-ticks",
    type=click.IntRange(min=1),
    default=None,
    help="Bound the loop to N ticks; production passes nothing (run until interrupted)",
)
@click.option(
    "--agents-md",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=_DEFAULT_AGENTS_MD,
    show_default=True,
)
@click.option(
    "--continuous-mode/--no-continuous-mode",
    default=False,
    show_default=True,
    help="Track D: wire the continuous trigger source into the tick loop. "
    "Default OFF = heartbeat-only. Wired-but-inert (NOT activated) when ON.",
)
@click.option(
    "--continuous-kill-switch/--no-continuous-kill-switch",
    default=False,
    show_default=True,
    help="Per-tenant kill-switch: forces continuous mode OFF for this tenant "
    "even when --continuous-mode is set (overrides the global enable).",
)
def run_cmd(
    customer_id: str,
    workspace_root: Path,
    tick_interval_seconds: float,
    max_ticks: int | None,
    agents_md: Path,
    continuous_mode: bool,
    continuous_kill_switch: bool,
) -> None:
    """Start the heartbeat loop (long-running by default)."""
    workspace_root.mkdir(parents=True, exist_ok=True)
    rules = load_routing_rules(agents_md)

    continuous_source, decision = _resolve_continuous_source(
        continuous_mode=continuous_mode,
        continuous_kill_switch=continuous_kill_switch,
    )
    # Track D D-2: resolve the per-tenant cadence (inert — surfaced in the decision
    # record, NOT registered with any driver; activation is v0.4).
    cadence = resolve_cadence(workspace_root=workspace_root, customer_id=customer_id)
    decision_record: dict[str, object] = {"customer_id": customer_id, **decision}
    decision_record["continuous_cadence"] = cadence.cadence if cadence else None
    # Audit/observability: record how continuous state resolved for this tenant.
    click.echo(json.dumps(decision_record, separators=(",", ":")))

    hb = Heartbeat(
        customer_id=customer_id,
        workspace_root=workspace_root,
        routing_rules=rules,
        continuous_source=continuous_source,
        tick_interval_seconds=tick_interval_seconds,
        max_ticks=max_ticks,
    )
    reports = asyncio.run(hb.run_forever())
    click.echo(f"ticks completed: {len(reports)}")
    if reports:
        click.echo(
            json.dumps(
                {
                    "first_tick_id": reports[0].tick_id,
                    "last_tick_id": reports[-1].tick_id,
                    "total_delegations": sum(r.total_delegations for r in reports),
                    "total_escalations": sum(r.total_escalations for r in reports),
                },
                separators=(",", ":"),
            )
        )


if __name__ == "__main__":
    main()
