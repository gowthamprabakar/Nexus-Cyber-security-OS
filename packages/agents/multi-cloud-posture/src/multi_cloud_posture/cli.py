"""Multi-Cloud Posture Agent CLI.

Two subcommands (mirrors D.4's CLI shape per ADR-007):

- `multi-cloud-posture eval CASES_DIR` — run the local eval suite at
  CASES_DIR via the eval-framework's `run_suite` against the
  registered `MultiCloudPostureEvalRunner`. Prints `<passed>/<total>
  passed` and exits non-zero if any case fails. The shipped suite
  lives at `packages/agents/multi-cloud-posture/eval/cases/`.

- `multi-cloud-posture run --contract path/to/contract.yaml [...]` —
  run the agent against an `ExecutionContract` YAML. Writes
  `findings.json` and `report.md` to the contract's workspace and
  prints a one-line digest. LLM provider is inferred from the
  environment via `charter.llm_adapter.config_from_env`; v0.1 doesn't
  call the LLM regardless (normalizers are deterministic).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from charter.contract import load_contract
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite

from multi_cloud_posture import __version__
from multi_cloud_posture.agent import run as agent_run
from multi_cloud_posture.eval_runner import MultiCloudPostureEvalRunner


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Multi-Cloud Posture Agent."""


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
    suite = asyncio.run(run_suite(cases, MultiCloudPostureEvalRunner()))
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
    "--azure-findings-feed",
    "azure_findings_feed",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to an Azure Defender for Cloud JSON export.",
)
@click.option(
    "--azure-activity-feed",
    "azure_activity_feed",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to an Azure Activity Log JSON export.",
)
@click.option(
    "--gcp-findings-feed",
    "gcp_findings_feed",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to a GCP Security Command Center findings JSON export.",
)
@click.option(
    "--gcp-iam-feed",
    "gcp_iam_feed",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to a GCP Cloud Asset Inventory IAM JSON export.",
)
@click.option(
    "--customer-domain",
    "customer_domains",
    multiple=True,
    default=(),
    help=(
        "Internal customer domain(s) for the GCP IAM external-user severity rule "
        "(repeatable). E.g. --customer-domain example.com --customer-domain corp.example.com"
    ),
)
def run_cmd(
    contract_path: Path,
    azure_findings_feed: Path | None,
    azure_activity_feed: Path | None,
    gcp_findings_feed: Path | None,
    gcp_iam_feed: Path | None,
    customer_domains: tuple[str, ...],
) -> None:
    """Run the Multi-Cloud Posture Agent against an ExecutionContract YAML."""
    contract = load_contract(contract_path)

    if not (azure_findings_feed or azure_activity_feed or gcp_findings_feed or gcp_iam_feed):
        click.echo(
            "warning: no feed flags provided; agent will emit an empty report",
            err=True,
        )

    report = asyncio.run(
        agent_run(
            contract=contract,
            azure_findings_feed=azure_findings_feed,
            azure_activity_feed=azure_activity_feed,
            gcp_findings_feed=gcp_findings_feed,
            gcp_iam_feed=gcp_iam_feed,
            customer_domain_allowlist=customer_domains,
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
