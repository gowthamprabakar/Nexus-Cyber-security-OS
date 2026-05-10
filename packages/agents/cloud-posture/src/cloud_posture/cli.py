"""Cloud Posture Agent CLI.

Two subcommands:

- `cloud-posture eval CASES_DIR` — run the local eval suite. Prints
  `<passed>/<total> passed` and exits non-zero if any case fails. The
  shipped suite lives at `packages/agents/cloud-posture/eval/cases/`.

- `cloud-posture run --contract path/to/contract.yaml` — run the agent
  against an `ExecutionContract` YAML. Writes `findings.json` and
  `summary.md` into the contract's workspace and prints the path. LLM
  provider and Neo4j driver are inferred from environment (NEXUS_LLM_*
  for the provider; KG persistence skipped if NEXUS_NEO4J_URI is unset).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from charter.contract import load_contract
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite

from cloud_posture import __version__
from cloud_posture.agent import run as agent_run
from cloud_posture.eval_runner import CloudPostureEvalRunner


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Cloud Posture Agent."""


# ---------------------- eval ------------------------------------------------


@main.command("eval")
@click.argument(
    "cases_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
def eval_cmd(cases_dir: Path) -> None:
    """Run the local eval suite at CASES_DIR.

    Exits 0 when every case passes, 1 otherwise. Prints one line per
    failing case with the failure_reason from the runner. Uses
    `eval_framework.run_suite` against the registered
    `CloudPostureEvalRunner`.
    """
    cases = load_cases(cases_dir)
    suite = asyncio.run(run_suite(cases, CloudPostureEvalRunner()))
    click.echo(f"{suite.passed}/{suite.total} passed")
    fail_count = 0
    for case in suite.cases:
        if not case.passed:
            click.echo(f"  FAIL {case.case_id}: {case.failure_reason} (actual={case.actuals})")
            fail_count += 1
    if fail_count:
        raise SystemExit(1)


# ---------------------- run -------------------------------------------------


@main.command("run")
@click.option(
    "--contract",
    "contract_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to an ExecutionContract YAML.",
)
@click.option(
    "--aws-account-id",
    default="111122223333",
    help="AWS account ID to scan. Defaults to the placeholder used in dev.",
)
@click.option(
    "--aws-region",
    default="us-east-1",
    help="AWS region to scan.",
)
def run_cmd(contract_path: Path, aws_account_id: str, aws_region: str) -> None:
    """Run the Cloud Posture Agent against an ExecutionContract YAML.

    LLM and Neo4j are not wired through here; the v0.1 deterministic flow
    does not call the LLM, and KG persistence is skipped (use the agent
    library API directly for KG-enabled runs).
    """
    contract = load_contract(contract_path)
    report = asyncio.run(
        agent_run(
            contract=contract,
            neo4j_driver=None,
            aws_account_id=aws_account_id,
            aws_region=aws_region,
        )
    )
    click.echo(f"agent: {report.agent} (v{report.agent_version})")
    click.echo(f"customer: {report.customer_id}")
    click.echo(f"run_id: {report.run_id}")
    click.echo(f"findings: {report.total}")
    counts = report.count_by_severity()
    for sev in ("critical", "high", "medium", "low", "info"):
        click.echo(f"  {sev}: {counts.get(sev, 0)}")
    click.echo(f"workspace: {contract.workspace}")


if __name__ == "__main__":
    main()
