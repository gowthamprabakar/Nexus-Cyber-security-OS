"""Runtime Threat Agent CLI.

Two subcommands (mirrors D.2's CLI shape per ADR-007):

- `runtime-threat-agent eval CASES_DIR` — run the local eval suite at
  CASES_DIR via the eval-framework's `run_suite` against the
  registered `RuntimeThreatEvalRunner`. Prints `<passed>/<total> passed`
  and exits non-zero if any case fails. The shipped suite lives at
  `packages/agents/runtime-threat/eval/cases/`.

- `runtime-threat-agent run --contract path/to/contract.yaml [...]` —
  run the agent against an `ExecutionContract` YAML. Writes
  `findings.json` and `summary.md` to the contract's workspace and
  prints a one-line digest. LLM provider is inferred from the
  environment via `charter.llm_adapter.config_from_env`; v0.1 doesn't
  call the LLM regardless.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from charter.contract import load_contract
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite

from runtime_threat import __version__
from runtime_threat.agent import run as agent_run
from runtime_threat.eval_runner import RuntimeThreatEvalRunner


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Runtime Threat Agent."""


# ---------------------- eval ---------------------------------------------


@main.command("eval")
@click.argument(
    "cases_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
def eval_cmd(cases_dir: Path) -> None:
    """Run the local eval suite at CASES_DIR.

    Exits 0 when every case passes, 1 otherwise. Prints one line per
    failing case with the failure_reason and actuals from the runner.
    """
    cases = load_cases(cases_dir)
    suite = asyncio.run(run_suite(cases, RuntimeThreatEvalRunner()))
    click.echo(f"{suite.passed}/{suite.total} passed")
    fail_count = 0
    for case in suite.cases:
        if not case.passed:
            click.echo(f"  FAIL {case.case_id}: {case.failure_reason} (actual={case.actuals})")
            fail_count += 1
    if fail_count:
        raise SystemExit(1)


# ---------------------- run ----------------------------------------------


@main.command("run")
@click.option(
    "--contract",
    "contract_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to an ExecutionContract YAML.",
)
@click.option(
    "--falco-feed",
    "falco_feed",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to a Falco JSONL alert feed.",
)
@click.option(
    "--tracee-feed",
    "tracee_feed",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to a Tracee JSONL alert feed.",
)
@click.option(
    "--osquery-pack",
    "osquery_pack",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to a .sql file (one query). Empty file skips OSQuery.",
)
@click.option(
    "--osquery-severity",
    "osquery_severity",
    type=int,
    default=2,
    show_default=True,
    help="Severity for OSQuery findings (0-3, same scale as Tracee).",
)
@click.option(
    "--osquery-finding-context",
    "osquery_finding_context",
    default="query_hit",
    show_default=True,
    help="Slug used in OSQuery findings' finding_id context segment.",
)
def run_cmd(
    contract_path: Path,
    falco_feed: Path | None,
    tracee_feed: Path | None,
    osquery_pack: Path | None,
    osquery_severity: int,
    osquery_finding_context: str,
) -> None:
    """Run the Runtime Threat Agent against an ExecutionContract YAML."""
    contract = load_contract(contract_path)

    if not (falco_feed or tracee_feed or osquery_pack):
        click.echo(
            "warning: no --falco-feed / --tracee-feed / --osquery-pack provided; "
            "agent will emit an empty report",
            err=True,
        )

    report = asyncio.run(
        agent_run(
            contract=contract,
            falco_feed=falco_feed,
            tracee_feed=tracee_feed,
            osquery_pack=osquery_pack,
            osquery_severity=osquery_severity,
            osquery_finding_context=osquery_finding_context,
        )
    )

    click.echo(f"agent: {report.agent} (v{report.agent_version})")
    click.echo(f"customer: {report.customer_id}")
    click.echo(f"run_id: {report.run_id}")
    click.echo(f"findings: {report.total}")
    counts = report.count_by_severity()
    for sev in ("critical", "high", "medium", "low", "info"):
        click.echo(f"  {sev}: {counts.get(sev, 0)}")
    type_counts = report.count_by_finding_type()
    for ft in (
        "runtime_process",
        "runtime_file",
        "runtime_network",
        "runtime_syscall",
        "runtime_osquery",
    ):
        click.echo(f"  {ft}: {type_counts.get(ft, 0)}")
    click.echo(f"workspace: {contract.workspace}")


if __name__ == "__main__":
    main()
