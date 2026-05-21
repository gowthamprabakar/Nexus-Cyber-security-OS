"""Meta-Harness Agent CLI.

Three subcommands (per plan Task 13):

- ``meta-harness eval [CASES_DIR]`` — run the local meta-eval suite
  at ``CASES_DIR`` via the eval-framework's ``run_suite`` against
  the registered ``MetaHarnessEvalRunner``. Prints
  ``<passed>/<total> passed`` and exits non-zero on any failure.
  Default ``CASES_DIR`` is the bundled ``eval/cases`` directory.

- ``meta-harness run --customer-id ID --run-id ID
  [--workspace-root .] [...]`` — run the 6-stage pipeline
  end-to-end against the registered ``nexus_eval_runners``. Q5
  single-tenant default: ``semantic_store=None`` unless future
  flag is wired. Writes ``<workspace-root>/meta_harness_report.md``
  + prints a one-line digest of agents evaluated + regressions.

- ``meta-harness ab-compare AGENT_ID --variant-a PATH
  --variant-b PATH [--customer-id ID] [--run-id ID]`` — run
  single-agent A/B compare against the named agent. Variant
  paths are two NLAH directories. Prints the WI-3 byte-equal
  flag + per-variant pass rates.

**A.4 is read-only in v0.1.** No subcommand writes to any agent's
NLAH directory. The report markdown goes to ``--workspace-root``;
KG persistence is opt-in (and v0.1's default remains None).
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite

from meta_harness import __version__
from meta_harness.agent import run as agent_run
from meta_harness.eval_runner import MetaHarnessEvalRunner

_LOG = logging.getLogger(__name__)
_DEFAULT_CASES_DIR = Path(__file__).parent.parent.parent / "eval" / "cases"


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Meta-Harness Agent — cross-agent batch eval, A/B compare, regression tracking."""


# ---------------------- eval --------------------------------------------


@main.command("eval")
@click.argument(
    "cases_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=False,
)
def eval_cmd(cases_dir: Path | None) -> None:
    """Run the local meta-eval suite at CASES_DIR.

    If CASES_DIR is omitted, the bundled suite at
    ``packages/agents/meta-harness/eval/cases/`` is used.

    Exits 0 when every case passes, 1 otherwise. Prints one line
    per failing case with the failure_reason and actuals.
    """
    target = cases_dir or _DEFAULT_CASES_DIR
    if not target.is_dir():
        click.echo(f"ERROR: cases dir not found: {target}", err=True)
        raise SystemExit(2)
    cases = load_cases(target)
    suite = asyncio.run(run_suite(cases, MetaHarnessEvalRunner()))
    passed = sum(1 for r in suite.cases if r.passed)
    total = len(suite.cases)
    click.echo(f"{passed}/{total} passed")
    failures = [r for r in suite.cases if not r.passed]
    for r in failures:
        click.echo(f"  FAIL {r.case_id}: {r.failure_reason}", err=True)
        if r.actuals:
            click.echo(f"    actuals: {r.actuals}", err=True)
    if failures:
        raise SystemExit(1)


# ---------------------- run ---------------------------------------------


@main.command("run")
@click.option("--customer-id", required=True, help="Tenant identifier")
@click.option("--run-id", required=True, help="A.4 run identifier (e.g. timestamp / ULID)")
@click.option(
    "--workspace-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path.cwd(),
    show_default=True,
    help="Root path the agent reads from and writes meta_harness_report.md to.",
)
def run_cmd(customer_id: str, run_id: str, workspace_root: Path) -> None:
    """Run the 6-stage pipeline against every registered nexus_eval_runners agent.

    Writes ``<workspace-root>/meta_harness_report.md``. Q5 single-
    tenant default: ``semantic_store=None`` (first-run deltas;
    no KG persistence) unless a future --semantic-store-dsn flag
    is wired post-SET-LOCAL-fix.
    """
    workspace_root.mkdir(parents=True, exist_ok=True)
    report = asyncio.run(
        agent_run(
            customer_id=customer_id,
            run_id=run_id,
            workspace_root=workspace_root,
        )
    )
    click.echo(
        f"evaluated {report.total_agents_evaluated} agent(s); "
        f"{report.successful_runs} successful; "
        f"{report.total_regressions} regression(s) flagged"
    )
    click.echo(f"report: {workspace_root / 'meta_harness_report.md'}")


# ---------------------- ab-compare --------------------------------------


@main.command("ab-compare")
@click.argument("agent_id")
@click.option(
    "--variant-a",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=True,
    help="Path to variant A's NLAH directory",
)
@click.option(
    "--variant-b",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    required=True,
    help="Path to variant B's NLAH directory",
)
@click.option("--customer-id", default="cli", show_default=True)
@click.option(
    "--run-id",
    default="ab-cli",
    show_default=True,
    help="A.4 run identifier (e.g. timestamp / ULID)",
)
@click.option(
    "--workspace-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path.cwd(),
    show_default=True,
)
def ab_compare_cmd(
    agent_id: str,
    variant_a: Path,
    variant_b: Path,
    customer_id: str,
    run_id: str,
    workspace_root: Path,
) -> None:
    """A/B-compare AGENT_ID's eval suite under two NLAH variants.

    Prints the WI-3 byte-equal flag + per-variant pass rates.
    Writes ``meta_harness_report.md`` with the A/B section
    populated.
    """
    workspace_root.mkdir(parents=True, exist_ok=True)
    report = asyncio.run(
        agent_run(
            customer_id=customer_id,
            run_id=run_id,
            workspace_root=workspace_root,
            ab_target_agent=agent_id,
            ab_variant_a=variant_a,
            ab_variant_b=variant_b,
            agent_filter=frozenset({agent_id}),
        )
    )
    ab = report.ab_comparison
    if ab is None:
        click.echo("A/B comparison did not run.", err=True)
        raise SystemExit(2)
    click.echo(
        f"agent_id={ab.agent_id}  "
        f"variant_a_pass={ab.variant_a_pass_rate * 100:.1f}%  "
        f"variant_b_pass={ab.variant_b_pass_rate * 100:.1f}%  "
        f"byte_equal={'YES' if ab.byte_equal else 'NO'}"
    )
    click.echo(f"report: {workspace_root / 'meta_harness_report.md'}")


if __name__ == "__main__":
    main()
