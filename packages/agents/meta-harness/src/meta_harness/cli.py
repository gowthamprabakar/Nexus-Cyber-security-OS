"""Meta-Harness Agent CLI.

Six subcommands (per plan Tasks 13 + 15):

Diagnostic (v0.1):

- ``meta-harness eval [CASES_DIR]`` — run the local meta-eval suite.
- ``meta-harness run --customer-id ID --run-id ID [...]`` — 8-stage pipeline.
- ``meta-harness ab-compare AGENT_ID --variant-a PATH --variant-b PATH`` —
  single-agent A/B compare.

Skill-curation (v0.2 / Task 15):

- ``meta-harness approve-skill SKILL_ID [--workspace-root .]`` — promote a
  pending candidate to canonical NLAH.
- ``meta-harness reject-skill SKILL_ID --reason TEXT [--workspace-root .]`` —
  reject a pending candidate.
- ``meta-harness list-skills [--workspace-root .]`` — list every pending
  candidate in the shadow tree.
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
from meta_harness.skill_approval import (
    approve_candidate,
    compute_notification_path,
    reject_candidate,
)
from meta_harness.skill_candidate_store import (
    CandidateNotFoundError,
    find_candidate_by_skill_id,
    list_pending_candidates,
)
from meta_harness.skill_registry import (
    load_skill_class_registry,
    save_skill_class_registry,
)

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


# ---------------------- skill curation (v0.2 / Task 15) -----------------


@main.command("approve-skill")
@click.argument("skill_id")
@click.option(
    "--workspace-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path.cwd(),
    show_default=True,
    help="Workspace root containing .nexus/ shadow tree and skill-class registry.",
)
def approve_skill_cmd(skill_id: str, workspace_root: Path) -> None:
    """Approve a pending skill candidate — first-of-class operator gate.

    Promotes the shadow SKILL.md to the canonical bundled NLAH path,
    registers the (agent_id, category) class, and removes the shadow.
    """
    try:
        candidate = find_candidate_by_skill_id(
            workspace_root=workspace_root,
            skill_id=skill_id,
        )
    except CandidateNotFoundError as exc:
        click.echo(f"ERROR: {exc}", err=True)
        raise SystemExit(1) from exc

    registry = load_skill_class_registry(workspace_root)
    decision, new_registry = approve_candidate(
        candidate,
        registry=registry,
        workspace_root=workspace_root,
    )
    save_skill_class_registry(new_registry, workspace_root=workspace_root)

    notification = compute_notification_path(workspace_root, skill_id)
    if notification.is_file():
        notification.unlink()

    click.echo(f"approved {skill_id} for agent {decision.target_agent} → {decision.deployed_path}")


@main.command("reject-skill")
@click.argument("skill_id")
@click.option(
    "--reason",
    required=True,
    help="Reason for rejection (recorded in the deployment decision).",
)
@click.option(
    "--workspace-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path.cwd(),
    show_default=True,
    help="Workspace root containing .nexus/ shadow tree.",
)
def reject_skill_cmd(skill_id: str, reason: str, workspace_root: Path) -> None:
    """Reject a pending skill candidate and remove its shadow.

    Used for operator-driven rejection. Also cleans up the pending-
    approval notification markdown if it exists.
    """
    try:
        candidate = find_candidate_by_skill_id(
            workspace_root=workspace_root,
            skill_id=skill_id,
        )
    except CandidateNotFoundError as exc:
        click.echo(f"ERROR: {exc}", err=True)
        raise SystemExit(1) from exc

    reject_candidate(
        candidate,
        rejection_reason=reason,
        workspace_root=workspace_root,
    )

    notification = compute_notification_path(workspace_root, skill_id)
    if notification.is_file():
        notification.unlink()

    click.echo(f"rejected {skill_id}: {reason}")


@main.command("list-skills")
@click.option(
    "--workspace-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path.cwd(),
    show_default=True,
    help="Workspace root containing .nexus/ shadow tree.",
)
def list_skills_cmd(workspace_root: Path) -> None:
    """List every pending skill candidate in the shadow tree."""
    candidates = list(list_pending_candidates(workspace_root))
    if not candidates:
        click.echo("no pending candidates")
        return
    for c in candidates:
        click.echo(
            f"{c.skill_id:40s}  agent={c.skill.target_agent:20s}  "
            f"status={c.skill.deployment_status.value}"
        )


if __name__ == "__main__":
    main()
