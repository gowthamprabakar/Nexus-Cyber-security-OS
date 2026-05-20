"""Compliance Agent CLI.

Two subcommands (mirrors D.8's CLI shape per ADR-007):

- ``compliance eval CASES_DIR`` — run the local eval suite at
  ``CASES_DIR`` via the eval-framework's ``run_suite`` against the
  registered :class:`ComplianceEvalRunner`. Prints
  ``<passed>/<total> passed`` and exits non-zero if any case
  fails. The shipped suite lives at
  ``packages/agents/compliance/eval/cases/``.

- ``compliance run --contract path/to/contract.yaml [...]`` — run
  the agent against an ``ExecutionContract`` YAML. Operator pins
  the two sibling workspaces via flags; writes ``findings.json``
  and ``report.md`` to the contract's workspace and prints a
  one-line digest.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from charter.contract import load_contract
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite

from compliance import __version__
from compliance.agent import run as agent_run
from compliance.eval_runner import ComplianceEvalRunner


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Compliance Agent — maps sibling-agent findings to CIS controls."""


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
    suite = asyncio.run(run_suite(cases, ComplianceEvalRunner()))
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
    "--cloud-posture-workspace",
    "cloud_posture_workspace",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Optional path to an F.3 Cloud Posture workspace (containing findings.json).",
)
@click.option(
    "--data-security-workspace",
    "data_security_workspace",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Optional path to a D.5 Data Security workspace (containing findings.json).",
)
def run_cmd(
    contract_path: Path,
    cloud_posture_workspace: Path | None,
    data_security_workspace: Path | None,
) -> None:
    """Run the Compliance Agent against an ExecutionContract YAML."""
    contract = load_contract(contract_path)

    if not (cloud_posture_workspace or data_security_workspace):
        click.echo(
            "warning: no --cloud-posture-workspace or --data-security-workspace provided; "
            "agent will emit an empty report (with the required CIS Benchmarks® attribution footer)",
            err=True,
        )

    report = asyncio.run(
        agent_run(
            contract=contract,
            cloud_posture_workspace=cloud_posture_workspace,
            data_security_workspace=data_security_workspace,
        )
    )

    click.echo(f"agent: {report.agent} (v{report.agent_version})")
    click.echo(f"customer: {report.customer_id}")
    click.echo(f"run_id: {report.run_id}")
    click.echo(f"failing controls: {report.total}")
    counts = report.count_by_severity()
    for sev in ("critical", "high", "medium", "low", "info"):
        click.echo(f"  {sev}: {counts.get(sev, 0)}")
    by_control = _count_by_control(report.findings)
    if by_control:
        click.echo("failing controls (by CIS id):")
        for control_id in sorted(by_control.keys()):
            click.echo(f"  {control_id}: {by_control[control_id]}")
    click.echo(f"workspace: {contract.workspace}")


def _count_by_control(findings: list[dict[str, object]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for raw in findings:
        compliance = raw.get("compliance")
        if not isinstance(compliance, dict):
            continue
        control = compliance.get("control")
        if isinstance(control, str):
            counts[control] = counts.get(control, 0) + 1
    return counts


if __name__ == "__main__":
    main()
