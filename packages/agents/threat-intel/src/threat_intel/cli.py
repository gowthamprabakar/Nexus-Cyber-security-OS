"""Threat Intel Agent CLI.

Two subcommands (mirrors D.4's CLI shape per ADR-007):

- ``threat-intel eval CASES_DIR`` — run the local eval suite at
  ``CASES_DIR`` via the eval-framework's ``run_suite`` against the
  registered :class:`ThreatIntelEvalRunner`. Prints
  ``<passed>/<total> passed`` and exits non-zero if any case fails.
  The shipped suite lives at
  ``packages/agents/threat-intel/eval/cases/``.

- ``threat-intel run --contract path/to/contract.yaml [...]`` — run
  the agent against an ``ExecutionContract`` YAML. Operator pins the
  three feed snapshots + three sibling workspaces via flags; writes
  ``findings.json`` and ``report.md`` to the contract's workspace
  and prints a one-line digest.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from charter.contract import load_contract
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite

from threat_intel import __version__
from threat_intel.agent import run as agent_run
from threat_intel.eval_runner import ThreatIntelEvalRunner
from threat_intel.schemas import ThreatIntelFindingType


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Threat Intel Agent."""


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
    suite = asyncio.run(run_suite(cases, ThreatIntelEvalRunner()))
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
    "--nvd-snapshot",
    "nvd_snapshot",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to an NVD CVE 2.0 JSON snapshot.",
)
@click.option(
    "--kev-snapshot",
    "kev_snapshot",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to a CISA KEV catalog JSON snapshot.",
)
@click.option(
    "--mitre-attack-snapshot",
    "mitre_attack_snapshot",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to a MITRE ATT&CK STIX 2.1 bundle JSON.",
)
@click.option(
    "--vulnerability-workspace",
    "vulnerability_workspace",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Optional path to a D.1 Vulnerability workspace (containing findings.json).",
)
@click.option(
    "--network-threat-workspace",
    "network_threat_workspace",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Optional path to a D.4 Network Threat workspace (containing findings.json).",
)
@click.option(
    "--runtime-threat-workspace",
    "runtime_threat_workspace",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Optional path to a D.3 Runtime Threat workspace (containing findings.json).",
)
def run_cmd(
    contract_path: Path,
    nvd_snapshot: Path | None,
    kev_snapshot: Path | None,
    mitre_attack_snapshot: Path | None,
    vulnerability_workspace: Path | None,
    network_threat_workspace: Path | None,
    runtime_threat_workspace: Path | None,
) -> None:
    """Run the Threat Intel Agent against an ExecutionContract YAML."""
    contract = load_contract(contract_path)

    no_feeds = not (nvd_snapshot or kev_snapshot or mitre_attack_snapshot)
    no_workspaces = not (
        vulnerability_workspace or network_threat_workspace or runtime_threat_workspace
    )
    if no_feeds and no_workspaces:
        click.echo(
            "warning: no --*-snapshot or --*-workspace provided; agent will emit "
            "an empty report (with the required MITRE ATT&CK attribution footer)",
            err=True,
        )

    report = asyncio.run(
        agent_run(
            contract=contract,
            nvd_snapshot=nvd_snapshot,
            kev_snapshot=kev_snapshot,
            mitre_attack_snapshot=mitre_attack_snapshot,
            vulnerability_workspace=vulnerability_workspace,
            network_threat_workspace=network_threat_workspace,
            runtime_threat_workspace=runtime_threat_workspace,
        )
    )

    click.echo(f"agent: {report.agent} (v{report.agent_version})")
    click.echo(f"customer: {report.customer_id}")
    click.echo(f"run_id: {report.run_id}")
    click.echo(f"findings: {report.total}")
    counts = report.count_by_severity()
    for sev in ("critical", "high", "medium", "low", "info"):
        click.echo(f"  {sev}: {counts.get(sev, 0)}")
    type_counts = _count_by_finding_type(report.findings)
    for ft in ThreatIntelFindingType:
        click.echo(f"  {ft.value}: {type_counts.get(ft.value, 0)}")
    click.echo(f"workspace: {contract.workspace}")


def _count_by_finding_type(findings: list[dict[str, object]]) -> dict[str, int]:
    counts: dict[str, int] = {ft.value: 0 for ft in ThreatIntelFindingType}
    for raw in findings:
        info = raw.get("finding_info") or {}
        if not isinstance(info, dict):
            continue
        types = info.get("types") or []
        if isinstance(types, list) and types and isinstance(types[0], str):
            counts[types[0]] = counts.get(types[0], 0) + 1
    return counts


if __name__ == "__main__":
    main()
