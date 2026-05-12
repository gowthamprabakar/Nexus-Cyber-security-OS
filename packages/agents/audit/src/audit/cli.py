"""Audit Agent CLI — F.6 Task 15.

Three subcommands:

- `audit-agent eval CASES_DIR` — run the eval suite. Exits 0 on full
  pass, 1 on any failure. Same shape as D.3's CLI.
- `audit-agent run --contract path.yaml [--source ...]` — drive the
  agent against an `ExecutionContract`. Writes `report.md` +
  `events.json` to the contract's workspace.
- `audit-agent query --tenant <id> [--source ...] [--format md|json|csv]` —
  the operator-facing read path. The default format is markdown;
  `--format json` emits the `AuditQueryResult.model_dump_json()`
  shape; `--format csv` emits one row per event.

**Exit-code convention** (drives downstream automation):

- `0` — clean run; query returned successfully and chain is valid.
- `1` — tooling failure (contract invalid, source unreachable, etc).
- `2` — chain tamper detected. A downstream cron job's pipeline can
  distinguish "tooling failure" from "tamper" without parsing
  stderr. F.6 is the only agent that emits 2 today.
"""

from __future__ import annotations

import asyncio
import csv
import io
from datetime import UTC, datetime
from pathlib import Path

import click
from charter.contract import load_contract
from charter.memory.models import Base
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from audit import __version__
from audit.agent import run as agent_run
from audit.chain import verify_audit_chain
from audit.eval_runner import AuditEvalRunner
from audit.schemas import AuditQueryResult
from audit.store import AuditStore
from audit.summarizer import render_markdown
from audit.tools.jsonl_reader import audit_jsonl_read


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Audit Agent — Nexus's hash-chained audit query surface."""


# ---------------------- eval --------------------------------------------


@main.command("eval")
@click.argument(
    "cases_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
def eval_cmd(cases_dir: Path) -> None:
    """Run the F.6 eval suite at CASES_DIR.

    Exits 0 on full pass, 1 on any failure.
    """
    cases = load_cases(cases_dir)
    suite = asyncio.run(run_suite(cases, AuditEvalRunner()))
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
    "--source",
    "sources",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True,
    help="Path to an audit.jsonl source. Repeat for multiple sources.",
)
def run_cmd(contract_path: Path, sources: tuple[Path, ...]) -> None:
    """Run the Audit Agent against an ExecutionContract YAML."""
    contract = load_contract(contract_path)
    workspace_root = Path(contract.workspace).parent
    workspace_root.mkdir(parents=True, exist_ok=True)

    async def _go() -> AuditQueryResult:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        try:
            return await agent_run(
                contract,
                audit_store=AuditStore(session_factory),
                sources=sources,
            )
        finally:
            await engine.dispose()

    result = asyncio.run(_go())
    click.echo(f"agent: audit (v{__version__})")
    click.echo(f"customer: {contract.customer_id}")
    click.echo(f"run_id: {contract.delegation_id}")
    click.echo(f"total: {result.total}")
    for action, count in result.count_by_action.items():
        click.echo(f"  {action}: {count}")


# ---------------------- query -------------------------------------------


@main.command("query")
@click.option(
    "--tenant",
    "tenant_id",
    required=True,
    help="Tenant ULID (26-char Crockford-base32).",
)
@click.option(
    "--source",
    "sources",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    multiple=True,
    help="Path to an audit.jsonl source. Repeat for multiple sources.",
)
@click.option(
    "--workspace",
    "workspace",
    type=click.Path(file_okay=False, path_type=Path),
    required=True,
    help="Directory to materialise an aiosqlite scratch DB + audit log.",
)
@click.option("--since", "since", default=None, help="ISO-8601 lower bound.")
@click.option("--until", "until", default=None, help="ISO-8601 upper bound.")
@click.option("--action", "action", default=None, help="Filter to one action.")
@click.option("--agent-id", "agent_id", default=None, help="Filter to one agent.")
@click.option(
    "--correlation-id",
    "correlation_id",
    default=None,
    help="Filter to one correlation_id.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["md", "markdown", "json", "csv"]),
    default="markdown",
    show_default=True,
    help="Output format.",
)
def query_cmd(
    tenant_id: str,
    sources: tuple[Path, ...],
    workspace: Path,
    since: str | None,
    until: str | None,
    action: str | None,
    agent_id: str | None,
    correlation_id: str | None,
    fmt: str,
) -> None:
    """Query the audit store. Exits 2 on chain tamper."""
    workspace.mkdir(parents=True, exist_ok=True)
    since_dt = _parse_iso(since)
    until_dt = _parse_iso(until)

    async def _go() -> tuple[AuditQueryResult, bool]:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        try:
            store = AuditStore(session_factory)

            # Ingest sources; track chain validity along the way.
            chain_valid = True
            for src in sources:
                events = await audit_jsonl_read(path=src, tenant_id=tenant_id)
                report = verify_audit_chain(events, sequential=True)
                if not report.valid:
                    chain_valid = False
                await store.ingest(tenant_id=tenant_id, events=events)

            result = await store.query(
                tenant_id=tenant_id,
                since=since_dt,
                until=until_dt,
                action=action,
                agent_id=agent_id,
                correlation_id=correlation_id,
            )
            return result, chain_valid
        finally:
            await engine.dispose()

    result, chain_valid = asyncio.run(_go())

    if fmt == "json":
        click.echo(result.model_dump_json())
    elif fmt == "csv":
        click.echo(_render_csv(result))
    else:
        click.echo(
            render_markdown(
                tenant_id=tenant_id,
                since=since_dt or datetime(2020, 1, 1, tzinfo=UTC),
                until=until_dt or datetime.now(UTC),
                result=result,
                chain=_chain_report(chain_valid, total=result.total),
            )
        )

    if not chain_valid:
        raise SystemExit(2)


# ---------------------- helpers -----------------------------------------


def _parse_iso(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _render_csv(result: AuditQueryResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(
        ["emitted_at", "tenant_id", "agent_id", "action", "correlation_id", "entry_hash"]
    )
    for event in result.events:
        writer.writerow(
            [
                event.emitted_at.isoformat(),
                event.tenant_id,
                event.agent_id,
                event.action,
                event.correlation_id,
                event.entry_hash,
            ]
        )
    return buf.getvalue().rstrip("\n")


def _chain_report(chain_valid: bool, *, total: int):  # type: ignore[no-untyped-def]
    from audit.schemas import ChainIntegrityReport

    if chain_valid:
        return ChainIntegrityReport(
            valid=True,
            entries_checked=total,
            broken_at_correlation_id=None,
            broken_at_action=None,
        )
    return ChainIntegrityReport(
        valid=False,
        entries_checked=total,
        broken_at_correlation_id="(see source jsonl)",
        broken_at_action="(see source jsonl)",
    )


if __name__ == "__main__":  # pragma: no cover
    main()
