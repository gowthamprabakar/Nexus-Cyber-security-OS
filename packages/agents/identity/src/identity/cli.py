"""Identity Agent CLI.

Two subcommands (mirrors D.1's CLI shape per ADR-007):

- `identity-agent eval CASES_DIR` — run the local eval suite at
  CASES_DIR via the eval-framework `run_suite` against the registered
  `IdentityEvalRunner`. Prints `<passed>/<total> passed` and exits
  non-zero if any case fails. The shipped suite lives at
  `packages/agents/identity/eval/cases/`.

- `identity-agent run --contract path/to/contract.yaml [...]` — run
  the agent against an `ExecutionContract` YAML. Writes
  `findings.json` and `summary.md` to the contract's workspace and
  prints a one-line digest. LLM provider is inferred from the
  environment via `charter.llm_adapter.config_from_env`; v0.1
  doesn't call the LLM regardless.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from charter.contract import load_contract
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite

from identity import __version__
from identity.agent import run as agent_run
from identity.eval_runner import IdentityEvalRunner


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Identity Agent."""


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
    Uses `eval_framework.run_suite` against the registered
    `IdentityEvalRunner`.
    """
    cases = load_cases(cases_dir)
    suite = asyncio.run(run_suite(cases, IdentityEvalRunner()))
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
    "--profile",
    "profile",
    default=None,
    help="Optional AWS named profile (defaults to environment auth).",
)
@click.option(
    "--region",
    "aws_region",
    default="us-east-1",
    show_default=True,
    help="AWS region for boto3 client construction (IAM is global).",
)
@click.option(
    "--analyzer-arn",
    "analyzer_arn",
    default=None,
    help="Access Analyzer ARN. When omitted, Access Analyzer is skipped.",
)
@click.option(
    "--mfa-user",
    "mfa_users",
    multiple=True,
    help=(
        "User name known to have MFA. Repeat for each. Anything with admin "
        "grants but missing here yields an MFA_GAP finding."
    ),
)
@click.option(
    "--dormant-threshold-days",
    "dormant_threshold_days",
    default=90,
    show_default=True,
    type=int,
    help="Last-used staleness threshold for dormant findings.",
)
def run_cmd(
    contract_path: Path,
    profile: str | None,
    aws_region: str,
    analyzer_arn: str | None,
    mfa_users: tuple[str, ...],
    dormant_threshold_days: int,
) -> None:
    """Run the Identity Agent against an ExecutionContract YAML."""
    contract = load_contract(contract_path)
    report = asyncio.run(
        agent_run(
            contract=contract,
            profile=profile,
            aws_region=aws_region,
            analyzer_arn=analyzer_arn,
            users_with_mfa=frozenset(mfa_users),
            dormant_threshold_days=dormant_threshold_days,
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
    for ft in ("overprivilege", "external_access", "mfa_gap", "admin_path", "dormant"):
        click.echo(f"  {ft}: {type_counts.get(ft, 0)}")
    click.echo(f"workspace: {contract.workspace}")


if __name__ == "__main__":
    main()
