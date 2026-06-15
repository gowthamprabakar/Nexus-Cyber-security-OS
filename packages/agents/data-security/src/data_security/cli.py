"""Data Security Agent CLI.

Two subcommands (mirrors multi-cloud-posture's CLI shape per ADR-007):

- ``data-security eval CASES_DIR`` — run the local eval suite at
  ``CASES_DIR`` via the eval-framework's ``run_suite`` against the
  registered ``DataSecurityEvalRunner``. Prints ``<passed>/<total>
  passed`` and exits non-zero if any case fails. The shipped suite
  lives at ``packages/agents/data-security/eval/cases/``.

- ``data-security run --contract path/to/contract.yaml [...]`` — run
  the agent against an ``ExecutionContract`` YAML. Writes
  ``findings.json`` and ``report.md`` to the contract's workspace and
  prints a one-line digest. LLM provider is inferred from the
  environment via ``charter.llm_adapter.config_from_env``; v0.1 doesn't
  call the LLM regardless (detectors + classifier are deterministic).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from charter.contract import load_contract
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite

from data_security import __version__
from data_security.agent import run as agent_run
from data_security.eval_runner import DataSecurityEvalRunner


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Data Security Agent (D.5)."""


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
    suite = asyncio.run(run_suite(cases, DataSecurityEvalRunner()))
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
    "--s3-inventory-feed",
    "s3_inventory_feed",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Optional path to a staged S3 bucket-inventory JSON (output of "
        "`aws s3api list-buckets` + per-bucket get-* calls, stitched)."
    ),
)
@click.option(
    "--s3-objects-feed",
    "s3_objects_feed",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Optional path to a staged S3 object-sample JSON "
        "({objects: [{bucket, key, content_sample_b64}]})."
    ),
)
@click.option(
    "--cloud-posture-workspace",
    "cloud_posture_workspace",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help=(
        "Optional path to a sibling F.3 cloud-posture workspace "
        "containing findings.json. Drives the CORRELATE stage (Q4)."
    ),
)
@click.option(
    "--vulnerability-workspace",
    "vulnerability_workspace",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help=(
        "Optional path to a sibling D.1 vulnerability workspace containing "
        "runtime_secrets.json. Emits OCSF 2003 SECRET_EXPOSED_IN_RUNTIME "
        "findings (A-2.4 / ADR-015: D.1 scans, DSPM emits)."
    ),
)
@click.option(
    "--appsec-workspace",
    "appsec_workspace",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help=(
        "Optional path to a sibling D.14 AppSec workspace containing "
        "code_secrets.json. Emits OCSF 2003 SECRET_EXPOSED_IN_CODE findings "
        "(B-1 / ADR-015: AppSec scans, DSPM emits)."
    ),
)
@click.option(
    "--trusted-sensitivity-tag",
    "trusted_sensitivity_tag",
    type=str,
    default="Restricted",
    show_default=True,
    help=("Override the trusted bucket-Sensitivity tag value for the sensitive-location detector."),
)
@click.option(
    "--customer-domain",
    "customer_domains",
    multiple=True,
    default=(),
    help=(
        "Internal customer domain(s) — reserved for D.5 v0.2 use "
        "(mirrors multi-cloud-posture's GCP IAM pattern; ignored in v0.1)."
    ),
)
def run_cmd(
    contract_path: Path,
    s3_inventory_feed: Path | None,
    s3_objects_feed: Path | None,
    cloud_posture_workspace: Path | None,
    vulnerability_workspace: Path | None,
    appsec_workspace: Path | None,
    trusted_sensitivity_tag: str,
    customer_domains: tuple[str, ...],
) -> None:
    """Run the Data Security Agent against an ExecutionContract YAML."""
    del customer_domains  # reserved for D.5 v0.2 (deferred classifier expansion).
    contract = load_contract(contract_path)

    if not (s3_inventory_feed or s3_objects_feed):
        click.echo(
            "warning: no S3 feeds provided; agent will emit an empty report",
            err=True,
        )

    report = asyncio.run(
        agent_run(
            contract=contract,
            s3_inventory_feed=s3_inventory_feed,
            s3_objects_feed=s3_objects_feed,
            cloud_posture_workspace=cloud_posture_workspace,
            vulnerability_workspace=vulnerability_workspace,
            appsec_workspace=appsec_workspace,
            trusted_sensitivity_tag=trusted_sensitivity_tag,
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
