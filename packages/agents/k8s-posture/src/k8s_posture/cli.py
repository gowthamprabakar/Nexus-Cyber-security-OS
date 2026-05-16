"""Kubernetes Posture Agent CLI.

Two subcommands (mirrors D.5's CLI shape per ADR-007):

- `k8s-posture eval CASES_DIR` — run the local eval suite at CASES_DIR
  via the eval-framework's `run_suite` against the registered
  `K8sPostureEvalRunner`. Prints `<passed>/<total> passed` and exits
  non-zero if any case fails. The shipped suite lives at
  `packages/agents/k8s-posture/eval/cases/`.

- `k8s-posture run --contract path/to/contract.yaml [...]` — run the
  agent against an `ExecutionContract` YAML. Writes `findings.json`
  and `report.md` to the contract's workspace and prints a one-line
  digest. v0.1 doesn't call the LLM (normalizers are deterministic).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from charter.contract import load_contract
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite

from k8s_posture import __version__
from k8s_posture.agent import run as agent_run
from k8s_posture.eval_runner import K8sPostureEvalRunner


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Kubernetes Posture Agent."""


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
    suite = asyncio.run(run_suite(cases, K8sPostureEvalRunner()))
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
    "--kube-bench-feed",
    "kube_bench_feed",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to a kube-bench --json output file.",
)
@click.option(
    "--polaris-feed",
    "polaris_feed",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to a polaris audit --format=json output file.",
)
@click.option(
    "--manifest-dir",
    "manifest_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Optional directory of Kubernetes manifests (*.yaml + *.yml). "
    "Mutually exclusive with --kubeconfig.",
)
@click.option(
    "--kubeconfig",
    "kubeconfig",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to a kubeconfig file for live cluster ingest (v0.2). "
    "Mutually exclusive with --manifest-dir.",
)
@click.option(
    "--cluster-namespace",
    "cluster_namespace",
    type=str,
    default=None,
    help="Optional namespace scope for live cluster ingest (used with --kubeconfig). "
    "Defaults to cluster-wide listing across all namespaces.",
)
def run_cmd(
    contract_path: Path,
    kube_bench_feed: Path | None,
    polaris_feed: Path | None,
    manifest_dir: Path | None,
    kubeconfig: Path | None,
    cluster_namespace: str | None,
) -> None:
    """Run the Kubernetes Posture Agent against an ExecutionContract YAML."""
    # Q6 — workload source XOR.
    if manifest_dir is not None and kubeconfig is not None:
        raise click.UsageError(
            "--manifest-dir and --kubeconfig are mutually exclusive — pick one "
            "workload source per run"
        )
    if cluster_namespace is not None and kubeconfig is None:
        raise click.UsageError(
            "--cluster-namespace requires --kubeconfig (it only scopes live ingest)"
        )

    contract = load_contract(contract_path)

    if not (kube_bench_feed or polaris_feed or manifest_dir or kubeconfig):
        click.echo(
            "warning: no feed flags provided; agent will emit an empty report",
            err=True,
        )

    report = asyncio.run(
        agent_run(
            contract=contract,
            kube_bench_feed=kube_bench_feed,
            polaris_feed=polaris_feed,
            manifest_dir=manifest_dir,
            kubeconfig=kubeconfig,
            cluster_namespace=cluster_namespace,
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
