"""Synthesis Agent CLI.

Two subcommands (mirrors D.6 / D.8's CLI shape per ADR-007):

- ``synthesis eval [CASES_DIR]`` — run the local eval suite at
  ``CASES_DIR`` via the eval-framework's ``run_suite`` against the
  registered ``SynthesisEvalRunner``. Prints
  ``<passed>/<total> passed`` and exits non-zero on any failure.
  Default ``CASES_DIR`` is the bundled ``eval/cases`` directory.

- ``synthesis run --contract path/to/contract.yaml [...]`` — run
  the agent against an ``ExecutionContract`` YAML. Operator pins
  the three sibling workspaces via flags; writes ``narrative.md``
  and ``executive_summary.md`` to the contract's workspace and
  prints a one-line digest.

**D.13 is the first agent that calls the LLM in its hot path.** The
``run`` subcommand reads ``charter.llm_adapter.config_from_env()``
to build an ``LLMProvider``; operators set ``NEXUS_LLM_PROVIDER`` +
``NEXUS_LLM_MODEL_PIN`` (and optionally ``NEXUS_LLM_API_KEY``) before
invoking. ``synthesis eval`` does not need a live provider — the
runner injects a deterministic stub.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import click
from charter.contract import load_contract
from charter.llm_adapter import config_from_env, make_provider
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite

from synthesis import __version__
from synthesis.agent import DEFAULT_MODEL_PIN
from synthesis.agent import run as agent_run
from synthesis.eval_runner import SynthesisEvalRunner

_DEFAULT_CASES_DIR = Path(__file__).parent.parent.parent / "eval" / "cases"


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Synthesis Agent — LLM-narrated synthesis over D.7 / D.6 / F.3."""


# ---------------------- eval ---------------------------------------------


@main.command("eval")
@click.argument(
    "cases_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=False,
)
def eval_cmd(cases_dir: Path | None) -> None:
    """Run the local eval suite at CASES_DIR.

    If CASES_DIR is omitted, the bundled suite at
    ``packages/agents/synthesis/eval/cases/`` is used.

    Exits 0 when every case passes, 1 otherwise. Prints one line
    per failing case with the failure_reason and actuals.
    """
    target = cases_dir or _DEFAULT_CASES_DIR
    if not target.is_dir():
        click.echo(f"ERROR: cases dir not found: {target}", err=True)
        raise SystemExit(2)
    cases = load_cases(target)
    suite = asyncio.run(run_suite(cases, SynthesisEvalRunner()))
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
    "--investigation-workspace",
    "investigation_workspace",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Optional path to a D.7 Investigation workspace (containing findings.json).",
)
@click.option(
    "--compliance-workspace",
    "compliance_workspace",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Optional path to a D.6 Compliance workspace (containing findings.json).",
)
@click.option(
    "--cloud-posture-workspace",
    "cloud_posture_workspace",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Optional path to an F.3 Cloud Posture workspace (containing findings.json).",
)
@click.option(
    "--model-pin",
    "model_pin",
    type=str,
    default=DEFAULT_MODEL_PIN,
    show_default=True,
    help="LLM model pin override.",
)
def run_cmd(
    contract_path: Path,
    investigation_workspace: Path | None,
    compliance_workspace: Path | None,
    cloud_posture_workspace: Path | None,
    model_pin: str,
) -> None:
    """Run the Synthesis Agent against an ExecutionContract YAML."""
    contract = load_contract(contract_path)

    if not (investigation_workspace or compliance_workspace or cloud_posture_workspace):
        click.echo(
            "warning: no --investigation-workspace / --compliance-workspace / "
            "--cloud-posture-workspace provided; synthesis will narrate zero findings",
            err=True,
        )

    try:
        llm_config = config_from_env()
    except ValueError as exc:
        click.echo(
            f"ERROR: LLM configuration missing. Set NEXUS_LLM_PROVIDER + "
            f"NEXUS_LLM_MODEL_PIN env vars before running. Detail: {exc}",
            err=True,
        )
        raise SystemExit(2) from exc

    llm_provider = make_provider(llm_config)

    report = asyncio.run(
        agent_run(
            contract=contract,
            llm_provider=llm_provider,
            investigation_workspace=investigation_workspace,
            compliance_workspace=compliance_workspace,
            cloud_posture_workspace=cloud_posture_workspace,
            model_pin=model_pin,
        )
    )

    click.echo(
        f"synthesis: {report.total_sections} sections | "
        f"{report.total_cited_findings} cited findings | "
        f"{report.review_retries} Q6 retries"
    )
    click.echo(f"customer: {report.customer_id}")
    click.echo(f"run_id: {report.run_id}")
    click.echo(f"workspace: {contract.workspace}")


if __name__ == "__main__":
    main()
