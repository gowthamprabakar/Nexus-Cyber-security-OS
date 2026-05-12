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
def run_cmd(
    contract_path: Path,
    sibling_workspaces: tuple[Path, ...],
    since: str | None,
    until: str | None,
) -> None:
    """Run the D.7 6-stage pipeline against an ExecutionContract YAML."""
    contract = load_contract(contract_path)
    report = asyncio.run(
        _drive(
            contract=contract,
            sibling_workspaces=sibling_workspaces,
            since=_parse_iso(since),
            until=_parse_iso(until),
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
def triage_cmd(
    contract_path: Path,
    sibling_workspaces: tuple[Path, ...],
) -> None:
    """Mode-A fast-path triage — concise summary for on-call paging."""
    contract = load_contract(contract_path)
    report = asyncio.run(
        _drive(
            contract=contract,
            sibling_workspaces=sibling_workspaces,
            since=None,
            until=None,
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
