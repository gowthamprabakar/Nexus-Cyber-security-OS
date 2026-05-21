"""Curiosity Agent CLI.

Two subcommands (mirrors D.6 / D.8 / D.13's CLI shape per ADR-007):

- ``curiosity eval [CASES_DIR]`` — run the local eval suite at
  ``CASES_DIR`` via the eval-framework's ``run_suite`` against the
  registered ``CuriosityEvalRunner``. Prints
  ``<passed>/<total> passed`` and exits non-zero on any failure.
  Default ``CASES_DIR`` is the bundled ``eval/cases`` directory.

- ``curiosity run --contract path/to/contract.yaml [...]`` — run
  the agent against an ``ExecutionContract`` YAML. Builds an
  ``LLMProvider`` from env vars; passes ``semantic_store=None`` +
  ``js_client=None`` by default per Q5 (production wires real
  instances when multi-tenant + NATS substrates are configured).
  Prints a one-line digest of hypothesis count + Q6 retries + gaps
  addressed.

**D.12 reads `SemanticStore` rather than sibling workspaces** — so
this CLI has no `--investigation-workspace` / `--compliance-
workspace` flags. Instead `--semantic-store-dsn` is an experimental
flag reserved for v0.2's multi-tenant production wiring; v0.1
logs a warning and proceeds with `semantic_store=None`.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click
from charter.contract import load_contract
from charter.llm_adapter import config_from_env, make_provider
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite

from curiosity import __version__
from curiosity.agent import DEFAULT_MODEL_PIN
from curiosity.agent import run as agent_run
from curiosity.eval_runner import CuriosityEvalRunner

_LOG = logging.getLogger(__name__)
_DEFAULT_CASES_DIR = Path(__file__).parent.parent.parent / "eval" / "cases"


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Curiosity Agent — proactive hypothesis-emission over SemanticStore state."""


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
    ``packages/agents/curiosity/eval/cases/`` is used.

    Exits 0 when every case passes, 1 otherwise. Prints one line
    per failing case with the failure_reason and actuals.
    """
    target = cases_dir or _DEFAULT_CASES_DIR
    if not target.is_dir():
        click.echo(f"ERROR: cases dir not found: {target}", err=True)
        raise SystemExit(2)
    cases = load_cases(target)
    suite = asyncio.run(run_suite(cases, CuriosityEvalRunner()))
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
    "--semantic-store-dsn",
    "semantic_store_dsn",
    type=str,
    default=None,
    help=(
        "EXPERIMENTAL: reserved for v0.2 multi-tenant production wiring. "
        "v0.1 ignores this flag and runs single-tenant (semantic_store=None)."
    ),
)
@click.option(
    "--nats-url",
    "nats_url",
    type=str,
    default=None,
    help=(
        "EXPERIMENTAL: reserved for v0.2 live `claims.>` publish wiring. "
        "v0.1 ignores this flag and runs without a JetStreamClient "
        "(js_client=None; claims.> publish no-ops)."
    ),
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
    semantic_store_dsn: str | None,
    nats_url: str | None,
    model_pin: str,
) -> None:
    """Run the Curiosity Agent against an ExecutionContract YAML."""
    contract = load_contract(contract_path)

    if semantic_store_dsn is not None:
        click.echo(
            "warning: --semantic-store-dsn is reserved for v0.2 multi-tenant "
            "production wiring; v0.1 ignores it and runs single-tenant.",
            err=True,
        )
    if nats_url is not None:
        click.echo(
            "warning: --nats-url is reserved for v0.2 live `claims.>` publish "
            "wiring; v0.1 ignores it and runs without a JetStreamClient.",
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
            semantic_store=None,
            js_client=None,
            model_pin=model_pin,
        )
    )

    click.echo(
        f"curiosity: {report.total_claims} hypotheses | "
        f"{report.total_gaps_addressed} gaps addressed | "
        f"{report.review_retries} Q6 retries"
    )
    click.echo(f"customer: {report.customer_id}")
    click.echo(f"run_id: {report.run_id}")
    click.echo(f"workspace: {contract.workspace}")


if __name__ == "__main__":
    main()
