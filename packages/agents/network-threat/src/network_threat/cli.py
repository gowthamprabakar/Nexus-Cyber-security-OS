"""Network Threat Agent CLI.

Two subcommands (mirrors D.3's CLI shape per ADR-007):

- `network-threat eval CASES_DIR` — run the local eval suite at
  CASES_DIR via the eval-framework's `run_suite` against the
  registered `NetworkThreatEvalRunner`. Prints `<passed>/<total>
  passed` and exits non-zero if any case fails. The shipped suite
  lives at `packages/agents/network-threat/eval/cases/`.

- `network-threat run --contract path/to/contract.yaml [...]` — run
  the agent against an `ExecutionContract` YAML. Writes
  `findings.json` and `report.md` to the contract's workspace and
  prints a one-line digest. LLM provider is inferred from the
  environment via `charter.llm_adapter.config_from_env`; v0.1 doesn't
  call the LLM regardless (detectors are deterministic).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from charter.contract import load_contract
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite

from network_threat import __version__
from network_threat.agent import run as agent_run
from network_threat.eval_runner import NetworkThreatEvalRunner


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Network Threat Agent."""


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
    suite = asyncio.run(run_suite(cases, NetworkThreatEvalRunner()))
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
    "--suricata-feed",
    "suricata_feed",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to a Suricata eve.json file (alert event_type only).",
)
@click.option(
    "--vpc-flow-feed",
    "vpc_flow_feed",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to an AWS VPC Flow Logs file (plaintext or gzipped).",
)
@click.option(
    "--dns-feed",
    "dns_feed",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to a DNS log file (BIND query log or Route 53 Resolver JSON).",
)
def run_cmd(
    contract_path: Path,
    suricata_feed: Path | None,
    vpc_flow_feed: Path | None,
    dns_feed: Path | None,
) -> None:
    """Run the Network Threat Agent against an ExecutionContract YAML."""
    contract = load_contract(contract_path)

    if not (suricata_feed or vpc_flow_feed or dns_feed):
        click.echo(
            "warning: no --suricata-feed / --vpc-flow-feed / --dns-feed provided; "
            "agent will emit an empty report",
            err=True,
        )

    report = asyncio.run(
        agent_run(
            contract=contract,
            suricata_feed=suricata_feed,
            vpc_flow_feed=vpc_flow_feed,
            dns_feed=dns_feed,
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
        "network_port_scan",
        "network_beacon",
        "network_dga",
        "network_suricata",
    ):
        click.echo(f"  {ft}: {type_counts.get(ft, 0)}")
    click.echo(f"workspace: {contract.workspace}")


if __name__ == "__main__":
    main()
