"""Remediation Agent CLI.

Two subcommands (mirrors D.6's shape per ADR-007):

- `remediation eval CASES_DIR` — run the eval suite at CASES_DIR via the
  eval-framework's `run_suite` against `RemediationEvalRunner`. Prints
  `<passed>/<total> passed` and exits non-zero on any failure.
- `remediation run --contract path/to/contract.yaml --findings path/to/findings.json
  --auth path/to/auth.yaml [--mode recommend|dry_run|execute]
  [--kubeconfig PATH | --in-cluster] [--cluster-namespace NS]
  [--rollback-window-sec INT]` — run the agent against an `ExecutionContract`
  with findings produced by a detect agent (D.6 today; D.5/F.3/D.1 later).
  Writes 7 output files to the contract workspace.

Mutual-exclusion gates and mode-escalation gates surface as `click.UsageError`
(non-zero exit, but with a usage prompt rather than a stack trace).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from charter.contract import load_contract
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite

from remediation import __version__
from remediation.agent import run as agent_run
from remediation.authz import Authorization, AuthorizationError
from remediation.eval_runner import RemediationEvalRunner
from remediation.schemas import RemediationMode

_MODE_CHOICES = [m.value for m in RemediationMode]


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Remediation Agent — recommend / dry-run / execute K8s remediations."""


# ---------------------- eval ---------------------------------------------


@main.command("eval")
@click.argument(
    "cases_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
def eval_cmd(cases_dir: Path) -> None:
    """Run the eval suite at CASES_DIR.

    Exits 0 when every case passes, 1 otherwise. Prints one line per failing
    case with the failure_reason and actuals from the runner.
    """
    cases = load_cases(cases_dir)
    suite = asyncio.run(run_suite(cases, RemediationEvalRunner()))
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
    "--findings",
    "findings_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to a findings.json produced by a detect agent (D.6 today).",
)
@click.option(
    "--auth",
    "auth_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to an authorization.yaml controlling mode flags, action allowlist, "
    "blast-radius cap, and rollback window. When omitted, defaults to the safest "
    "no-op (recommend-only mode, empty allowlist).",
)
@click.option(
    "--mode",
    "mode_str",
    type=click.Choice(_MODE_CHOICES, case_sensitive=False),
    default=RemediationMode.RECOMMEND.value,
    show_default=True,
    help="Operational tier. `recommend` generates artifacts only; `dry_run` adds "
    "kubectl --dry-run=server; `execute` applies for real with mandatory "
    "post-validation + rollback.",
)
@click.option(
    "--kubeconfig",
    "kubeconfig",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to a kubeconfig for cluster access. Mutually exclusive "
    "with --in-cluster. Required for dry_run / execute modes (no live cluster "
    "in recommend mode).",
)
@click.option(
    "--in-cluster",
    "in_cluster",
    is_flag=True,
    default=False,
    help="Load cluster config from the Pod's mounted ServiceAccount token. "
    "Mutually exclusive with --kubeconfig. Use this when running the agent as a "
    "Pod inside the cluster being patched.",
)
@click.option(
    "--cluster-namespace",
    "cluster_namespace",
    type=str,
    default=None,
    help="Override the namespace scope for the post-validation D.6 re-run "
    "(Stage 6). Defaults to each artifact's own namespace.",
)
@click.option(
    "--rollback-window-sec",
    "rollback_window_sec",
    type=click.IntRange(min=60, max=1800),
    default=None,
    help="Override `rollback_window_sec` from auth.yaml (60-1800). The validator "
    "waits this long between apply and re-detect before deciding rollback.",
)
@click.option(
    "--i-understand-this-applies-patches-to-the-cluster",
    "enable_execute",
    is_flag=True,
    default=False,
    help="REQUIRED to pass `--mode execute`. Operational kill-switch independent "
    "of auth.yaml: even an over-broad `auth.yaml` cannot apply patches without "
    "this flag also being supplied at the command line. Default is OFF; "
    "`recommend` and `dry_run` modes do not require it. Until A.1's safety "
    "contract has been proven against a live cluster (gate G3 of the four-gate "
    "plan), this flag should remain unset in any environment that holds real "
    "workloads. See: docs/_meta/a1-safety-verification-2026-05-16.md.",
)
def run_cmd(
    contract_path: Path,
    findings_path: Path,
    auth_path: Path | None,
    mode_str: str,
    kubeconfig: Path | None,
    in_cluster: bool,
    cluster_namespace: str | None,
    rollback_window_sec: int | None,
    enable_execute: bool,
) -> None:
    """Run the Remediation Agent end-to-end."""
    mode = RemediationMode(mode_str.lower())

    if kubeconfig is not None and in_cluster:
        raise click.UsageError(
            "--kubeconfig and --in-cluster are mutually exclusive — pick one cluster-access mode"
        )

    if mode != RemediationMode.RECOMMEND and not (kubeconfig or in_cluster):
        raise click.UsageError(
            f"--mode {mode.value} requires cluster access — supply --kubeconfig or --in-cluster"
        )

    if mode == RemediationMode.EXECUTE and not enable_execute:
        raise click.UsageError(
            "--mode execute is locked OFF by default. Pass "
            "`--i-understand-this-applies-patches-to-the-cluster` to enable it. "
            "This flag is an operational kill-switch independent of auth.yaml: "
            "both layers must agree before the agent applies patches. "
            "`recommend` and `dry_run` modes do not require this flag — use one "
            "of those to preview the patches first."
        )

    auth = Authorization.from_path(auth_path) if auth_path else Authorization.recommend_only()
    if rollback_window_sec is not None:
        auth = auth.model_copy(update={"rollback_window_sec": rollback_window_sec})

    contract = load_contract(contract_path)

    try:
        report = asyncio.run(
            agent_run(
                contract=contract,
                findings_path=findings_path,
                mode=mode,
                authorization=auth,
                kubeconfig=kubeconfig,
                in_cluster=in_cluster,
                cluster_namespace=cluster_namespace,
            )
        )
    except AuthorizationError as exc:
        # Mode-escalation refusal surfaces as a usage error with the contract's
        # required opt-in field name in the message.
        raise click.UsageError(str(exc)) from exc

    click.echo(f"agent: {report.agent} (v{report.agent_version})")
    click.echo(f"customer: {report.customer_id}")
    click.echo(f"run_id: {report.run_id}")
    click.echo(f"mode: {report.mode.value}")
    click.echo(f"findings: {report.total}")
    counts = report.count_by_outcome()
    for outcome_name, count in counts.items():
        if count > 0:
            click.echo(f"  {outcome_name}: {count}")
    click.echo(f"workspace: {contract.workspace}")


if __name__ == "__main__":
    main()
