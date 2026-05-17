"""Investigation Agent CLI — D.7 Task 15.

Three subcommands:

- `investigation-agent eval CASES_DIR` — runs the eval suite via the
  registered `InvestigationEvalRunner`. Exits 0 on full pass, 1 on
  any failure. Same shape as F.6 / D.3.
- `investigation-agent run --contract path.yaml [--sibling-workspace ...]`
  — drives the 6-stage pipeline against an `ExecutionContract`.
  Writes the 4 artifacts to the contract workspace and prints a
  one-screen digest.
- `investigation-agent triage --contract path.yaml [--sibling-workspace ...]`
  — Mode-A fast path. Same pipeline (D.7's pipeline doesn't currently
  have a separate "shallow" mode in v0.1), but prints a one-line
  confidence + hypothesis-count summary suitable for on-call paging.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import click
from audit.store import AuditStore
from charter.contract import load_contract
from charter.memory import SemanticStore
from charter.memory.models import Base
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from investigation import __version__
from investigation.agent import run as agent_run
from investigation.eval_runner import InvestigationEvalRunner
from investigation.schemas import IncidentReport

PUBLISH_FLAG_ENV_VAR = "NEXUS_FABRIC_PUBLISH"
"""Env var that flips F.7 fabric publishing on per F.7 v0.2 plan Q3.

Truthy values (case-insensitive): "1", "true", "yes". Anything else (or
unset) is False. The CLI flag `--publish-events-to-bus` /
`--no-publish-events-to-bus` overrides this env var when explicitly
passed.
"""

_PUBLISH_FLAG_TRUTHY = frozenset({"1", "true", "yes"})


def _resolve_publish_flag(cli_value: bool | None) -> bool:
    """Resolve the publish-events-to-bus flag with the F.7 v0.2 Q3 precedence.

    1. Explicit CLI flag wins when the user passed either form
       (`--publish-events-to-bus` or `--no-publish-events-to-bus`).
    2. Otherwise consult `NEXUS_FABRIC_PUBLISH` env var (truthy values:
       1 / true / yes, case-insensitive).
    3. Otherwise default to False (the v0.2-safe-default).
    """
    if cli_value is not None:
        return cli_value
    raw = os.environ.get(PUBLISH_FLAG_ENV_VAR, "").strip().lower()
    return raw in _PUBLISH_FLAG_TRUTHY


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Investigation Agent — Orchestrator-Workers forensic correlator."""


# ---------------------- eval --------------------------------------------


@main.command("eval")
@click.argument(
    "cases_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
def eval_cmd(cases_dir: Path) -> None:
    """Run the D.7 eval suite at CASES_DIR.

    Exits 0 on full pass, 1 on any failure.
    """
    cases = load_cases(cases_dir)
    suite = asyncio.run(run_suite(cases, InvestigationEvalRunner()))
    click.echo(f"{suite.passed}/{suite.total} passed")
    fail_count = 0
    for case in suite.cases:
        if not case.passed:
            click.echo(f"  FAIL {case.case_id}: {case.failure_reason} (actual={case.actuals})")
            fail_count += 1
    if fail_count:
        raise SystemExit(1)


# ---------------------- run ---------------------------------------------


@main.command("run")
@click.option(
    "--contract",
    "contract_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to an ExecutionContract YAML.",
)
@click.option(
    "--sibling-workspace",
    "sibling_workspaces",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    multiple=True,
    help="Sibling-agent workspace containing findings.json. Repeat for multiple.",
)
@click.option(
    "--since",
    "since",
    type=str,
    default=None,
    help="ISO-8601 lower bound on the investigation window (e.g. 2026-05-01T00:00:00Z).",
)
@click.option(
    "--until",
    "until",
    type=str,
    default=None,
    help="ISO-8601 upper bound on the investigation window.",
)
@click.option(
    "--publish-events-to-bus/--no-publish-events-to-bus",
    "publish_events_to_bus",
    default=None,
    help=(
        "Publish D.7 lifecycle events (started / completed / failed) to the "
        "F.7 fabric bus (events.>). Default: off. Env var "
        f"{PUBLISH_FLAG_ENV_VAR}=1 is the secondary control; the explicit "
        "CLI flag wins when both are set. v0.2 wires the flag only; the "
        "agent driver does not yet branch on it (Task 3 lands that)."
    ),
)
def run_cmd(
    contract_path: Path,
    sibling_workspaces: tuple[Path, ...],
    since: str | None,
    until: str | None,
    publish_events_to_bus: bool | None,
) -> None:
    """Run the D.7 6-stage pipeline against an ExecutionContract YAML."""
    contract = load_contract(contract_path)
    report = asyncio.run(
        _drive(
            contract=contract,
            sibling_workspaces=sibling_workspaces,
            since=_parse_iso(since),
            until=_parse_iso(until),
            publish_events_to_bus=_resolve_publish_flag(publish_events_to_bus),
        )
    )
    _print_full_digest(report)


# ---------------------- triage ------------------------------------------


@main.command("triage")
@click.option(
    "--contract",
    "contract_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to an ExecutionContract YAML.",
)
@click.option(
    "--sibling-workspace",
    "sibling_workspaces",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    multiple=True,
    help="Sibling-agent workspace containing findings.json. Repeat for multiple.",
)
@click.option(
    "--publish-events-to-bus/--no-publish-events-to-bus",
    "publish_events_to_bus",
    default=None,
    help=(
        "Publish D.7 lifecycle events (started / completed / failed) to the "
        "F.7 fabric bus (events.>). Default: off. Env var "
        f"{PUBLISH_FLAG_ENV_VAR}=1 is the secondary control; the explicit "
        "CLI flag wins when both are set."
    ),
)
def triage_cmd(
    contract_path: Path,
    sibling_workspaces: tuple[Path, ...],
    publish_events_to_bus: bool | None,
) -> None:
    """Mode-A fast-path triage — concise summary for on-call paging."""
    contract = load_contract(contract_path)
    report = asyncio.run(
        _drive(
            contract=contract,
            sibling_workspaces=sibling_workspaces,
            since=None,
            until=None,
            publish_events_to_bus=_resolve_publish_flag(publish_events_to_bus),
        )
    )
    _print_triage_summary(report)


# ---------------------- helpers -----------------------------------------


async def _drive(
    *,
    contract: Any,
    sibling_workspaces: tuple[Path, ...],
    since: datetime | None,
    until: datetime | None,
    publish_events_to_bus: bool = False,
) -> IncidentReport:
    """Bring up an in-memory aiosqlite substrate + run the agent."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    audit_store = AuditStore(session_factory)
    semantic_store = SemanticStore(session_factory)

    try:
        return await agent_run(
            contract,
            audit_store=audit_store,
            semantic_store=semantic_store,
            llm_provider=None,
            sibling_workspaces=sibling_workspaces,
            since=since,
            until=until,
            publish_events_to_bus=publish_events_to_bus,
        )
    finally:
        await engine.dispose()


def _print_full_digest(report: IncidentReport) -> None:
    click.echo(f"agent: investigation (v{__version__})")
    click.echo(f"incident_id: {report.incident_id}")
    click.echo(f"tenant: {report.tenant_id}")
    click.echo(f"correlation_id: {report.correlation_id}")
    click.echo(f"confidence: {report.confidence:.2f}")
    click.echo(f"hypotheses: {len(report.hypotheses)}")
    click.echo(f"timeline events: {len(report.timeline.events)}")
    click.echo(f"iocs: {len(report.iocs)}")
    click.echo(f"mitre techniques: {len(report.mitre_techniques)}")
    if report.hypotheses:
        click.echo("Hypotheses:")
        for h in report.hypotheses:
            click.echo(f"  - {h.hypothesis_id} ({h.confidence:.2f}): {h.statement[:80]}")


def _print_triage_summary(report: IncidentReport) -> None:
    click.echo(f"Triage summary — incident {report.incident_id}")
    click.echo(f"  tenant: {report.tenant_id}")
    click.echo(f"  confidence: {report.confidence:.2f}")
    click.echo(f"  hypotheses: {len(report.hypotheses)}")
    click.echo(f"  timeline events: {len(report.timeline.events)}")
    if report.hypotheses:
        top = report.hypotheses[0]
        click.echo(f"  top hypothesis: {top.statement[:120]}")


def _parse_iso(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


if __name__ == "__main__":  # pragma: no cover
    main()
