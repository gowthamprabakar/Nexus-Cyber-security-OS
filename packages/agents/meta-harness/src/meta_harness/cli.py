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
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import click
from charter.audit import AuditLog
from eval_framework.cases import load_cases
from eval_framework.suite import run_suite

from meta_harness import __version__
from meta_harness.agent import run as agent_run
from meta_harness.effectiveness_compat import apply_backwards_compat_reason
from meta_harness.effectiveness_store import (
    list_deployed_skills_with_scores,
    write_effectiveness_score,
)
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
from meta_harness.skill_effectiveness import compute_effectiveness_score
from meta_harness.skill_feedback import _operator_ratings_path
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


# ---------------------- score-effectiveness (v0.2.5 / Task 11) ------------


@main.command("score-effectiveness")
@click.option(
    "--agent",
    "agent_id",
    default=None,
    help="Scope to a specific agent.",
)
@click.option(
    "--skill",
    "skill_id",
    default=None,
    help="Scope to a specific skill (requires --agent).",
)
@click.option(
    "--tenant",
    "tenant_id",
    default="default",
    show_default=True,
    help="Scope to a specific tenant.",
)
@click.option(
    "--workspace-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path.cwd(),
    show_default=True,
    help="Workspace root containing .nexus/deployed-skills/.",
)
def score_effectiveness_cmd(
    agent_id: str | None,
    skill_id: str | None,
    tenant_id: str,
    workspace_root: Path,
) -> None:
    """Compute and persist effectiveness scores for deployed skills.

    Without flags, aggregates all deployed skills across all agents.
    Use --agent to scope to a specific agent, --skill + --agent for a
    single skill.
    """
    if skill_id is not None and agent_id is None:
        click.echo("ERROR: --skill requires --agent", err=True)
        raise SystemExit(2)

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    audit_path = workspace_root / ".nexus" / "audit" / f"cli-score-{run_id}.jsonl"
    audit_log = AuditLog(audit_path, agent="meta-harness-cli", run_id=run_id)

    # Collect (agent_id, skill_id) pairs.
    pairs: list[tuple[str, str]]
    if agent_id is not None and skill_id is not None:
        pairs = [(agent_id, skill_id)]
    elif agent_id is not None:
        all_results = list_deployed_skills_with_scores(workspace_root, tenant_id=tenant_id)
        pairs = [(a, s) for a, s, _ in all_results if a == agent_id]
    else:
        all_results = list_deployed_skills_with_scores(workspace_root, tenant_id=tenant_id)
        pairs = [(a, s) for a, s, _ in all_results]

    if not pairs:
        click.echo("no deployed skills found")
        return

    scores: list[tuple[str, str, str, str, str]] = []
    for aid, sid in pairs:
        try:
            score = compute_effectiveness_score(
                skill_id=sid,
                agent_id=aid,
                audit_log=audit_log,
                workspace_root=workspace_root,
                tenant_id=tenant_id,
            )
            score = apply_backwards_compat_reason(
                score,
                agent_id=aid,
                audit_log=audit_log,
                workspace_root=workspace_root,
            )
            write_effectiveness_score(score, audit_log=audit_log, workspace_root=workspace_root)
        except Exception as err:
            click.echo(f"FAIL {aid}/{sid}: computation error", err=True)
            _LOG.exception("score-effectiveness failed for %s/%s", aid, sid)
            raise SystemExit(1) from err

        gs = f"{score.global_score:.3f}" if score.global_score is not None else "N/A"
        conf = f"{score.confidence:.2f}"
        reason = score.reason.value if score.reason else "-"
        scores.append((aid, sid, gs, conf, reason))

    # Print table.
    header = f"{'AGENT':30s} {'SKILL':40s} {'SCORE':>7s} {'CONF':>6s} {'REASON'}"
    click.echo(header)
    click.echo("-" * len(header))
    for aid, sid, gs, conf, reason in sorted(scores):
        click.echo(f"{aid:30s} {sid:40s} {gs:>7s} {conf:>6s} {reason}")


# ---------------------- rate-skill (v0.2.5 / Task 11) --------------------


@main.command("rate-skill")
@click.argument("skill_id")
@click.option(
    "--rating",
    type=click.Choice(["useful", "neutral", "harmful"]),
    required=True,
    help="Operator rating for the skill.",
)
@click.option("--note", default=None, help="One-line note attached to the rating.")
@click.option(
    "--note-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="File containing a multi-line note.",
)
@click.option(
    "--agent",
    "agent_id",
    default="default-agent",
    show_default=True,
    help="Agent that owns the skill.",
)
@click.option(
    "--tenant",
    "tenant_id",
    default="default",
    show_default=True,
    help="Tenant scope for the rating.",
)
@click.option(
    "--workspace-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path.cwd(),
    show_default=True,
    help="Workspace root for audit chain and sidecar.",
)
def rate_skill_cmd(
    skill_id: str,
    rating: str,
    note: str | None,
    note_file: Path | None,
    agent_id: str,
    tenant_id: str,
    workspace_root: Path,
) -> None:
    """Record an operator rating for a deployed skill.

    Ratings are written to the audit chain (canonical source per Q8)
    and appended to the sidecar operator-ratings.jsonl projection.
    """
    if note_file is not None:
        note = note_file.read_text(encoding="utf-8").strip()

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    audit_path = workspace_root / ".nexus" / "audit" / f"cli-rate-{run_id}.jsonl"
    audit_log = AuditLog(audit_path, agent="meta-harness-cli", run_id=run_id)

    rated_at = datetime.now(UTC).isoformat()
    payload: dict[str, object] = {
        "action": "agent.skill.operator_rated",
        "skill_id": skill_id,
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "rating": rating,
        "rated_by": "cli-operator",
        "rated_at": rated_at,
    }
    if note:
        payload["note"] = note

    # Primary: audit chain (canonical per Q8).
    audit_log.append("agent.skill.operator_rated", payload)

    # Secondary: sidecar projection (cross-run persistence, CF #6).
    sidecar_path = _operator_ratings_path(workspace_root, agent_id, skill_id)
    sidecar_path.parent.mkdir(parents=True, exist_ok=True)
    with open(sidecar_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload, sort_keys=True) + "\n")

    click.echo(f"rated {skill_id} as {rating} at {rated_at}")
    if note:
        click.echo(f"note: {note}")


# ---------------------- attack-paths (the North Star surface) ------------


@main.command("attack-paths")
@click.option("--customer-id", required=True, help="Tenant identifier")
@click.option(
    "--dsn",
    envvar="NEXUS_MEMORY_DSN",
    required=True,
    help="Postgres DSN for the fleet graph (or set NEXUS_MEMORY_DSN)",
)
@click.option("--limit", default=10, show_default=True, help="Max paths to show")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of a text report")
def attack_paths_cmd(customer_id: str, dsn: str, limit: int, as_json: bool) -> None:
    """Connect to the fleet graph and print a tenant's top attack paths, worst-first.

    The North Star surface: runs the cross-agent bridges, then ranks the confirmed (named) +
    candidate (generic) attack paths. Requires a populated graph (the agents' scan writes it).
    """
    import asyncio as _asyncio
    import json as _json

    from charter.memory.provisioning import build_session_factory
    from charter.memory.semantic import SemanticStore

    from meta_harness.attack_path_report import (
        candidate_to_dict,
        path_to_dict,
        render_candidates,
        render_report,
    )
    from meta_harness.scan import analyze

    async def _run() -> None:
        factory = await build_session_factory(dsn)
        result = await analyze(SemanticStore(factory), customer_id)
        if as_json:
            click.echo(
                _json.dumps(
                    {
                        "confirmed": [path_to_dict(p) for p in result.confirmed[:limit]],
                        "candidates": [candidate_to_dict(c) for c in result.candidates],
                    },
                    indent=2,
                )
            )
        else:
            click.echo(render_report(result.confirmed, tenant_id=customer_id, limit=limit))
            click.echo()
            click.echo(render_candidates(result.candidates, tenant_id=customer_id))

    _asyncio.run(_run())


if __name__ == "__main__":
    main()
