"""Meta-Harness Agent driver — wires the 8-stage v0.2 pipeline.

Task 10 of the A.4 v0.1 plan + Task 13 of the A.4 v0.2 plan. One
fewer stage than D.12 still (no PUBLISH — A.4 doesn't emit on any
fabric bus).

Eight-stage pipeline (v0.2; v0.1 had six, Stages 6 + 7 are new and
the old Stage 6 became Stage 8):

  1. INTROSPECT       — parse each evaluated agent's NLAH directory.
  2. BATCH_EVAL       — run each agent's eval suite (BatchEvalRunner).
  3. AB_COMPARE       — optional; only when --ab subcommand invoked
                        (variant_a, variant_b, target_agent all set).
  4. DELTA            — diff current Scorecards against previous-run
                        entities loaded from SemanticStore.
  5. REPORT           — assemble MetaHarnessReport via
                        flag_regressions + reporter.render_report.
  6. SKILL_TRIGGER    — NEW v0.2. Walk each agent's audit-chain entries
                        + apply ``detect_skill_trigger`` (Task 6) against
                        the registry's deployed-hash set (Task 9).
  7. SKILL_CREATE     — NEW v0.2. LLM-compose candidate SKILL.md
                        (Task 7) → eval-gate (Task 8) → approve / auto-
                        deploy / reject (Task 10) + audit emissions
                        (Task 12). Persists the skill-class registry.
                        Implementation lives in ``skill_lifecycle.py``.
  8. HANDOFF          — RENAMED from v0.1 Stage 6. Writes
                        meta_harness_report.md to workspace + persists
                        agent_scorecard / ab_comparison_result entities
                        (Q5 opt-in).

**Backwards-compat (drift #5 / Task 1 v0.2 regression probe).** Stages
6 + 7 are SKIPPED when any of ``llm_provider``, ``audit_chain_loader``,
``eval_runner_loader`` is ``None``. The report's ``skill_lifecycle``
field is the all-empty ``SkillLifecycleSummary()`` default — v0.1-
equivalent shape with no behavioural change.

**Q5 single-tenant.** ``semantic_store`` defaults to ``None``.
Production wires a real instance when the SET LOCAL ``$1``
tenant-RLS substrate-fix lands; v0.1 default exercises the no-op
paths cleanly.

**v0.2 write surface.** A.4 v0.2 introduces deliberate writes outside
``meta_harness_report.md``: shadow SKILL.md candidates at
``<workspace>/.nexus/candidate-skills/<agent>/<skill_id>/SKILL.md``
(Task 7) and, on auto-deploy / operator approval, canonical SKILL.md
at ``packages/agents/<agent>/src/<agent>/nlah/skills/<skill_id>/SKILL.md``
(Task 10). The Q-ARCH-1 fence on ``claims.>`` (Task 11 / ADR-012 v1.1)
guards what those writes are allowed to consume.

**Q-ARCH-2 reminder.** Still no fabric publish.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from charter.llm import LLMProvider
from charter.memory.semantic import EntityRow, SemanticStore

from meta_harness.entities import ABComparisonResult, AgentScorecard
from meta_harness.eval.batch import (
    BatchEvalConfig,
    BatchEvalRunner,
    CasesRootResolver,
    default_cases_root,
)
from meta_harness.kg_writer import upsert_ab_result, upsert_scorecards
from meta_harness.reporter import render_report
from meta_harness.schemas import (
    ABComparison,
    AgentManifest,
    MetaHarnessReport,
    Scorecard,
    ScorecardDelta,
    SkillLifecycleSummary,
)
from meta_harness.skill_lifecycle import (
    AuditChainLoader,
    EvalRunnerLoader,
    run_skill_lifecycle,
)
from meta_harness.tools.ab_compare import (
    ABCompareRequest,
    ab_compare,
)
from meta_harness.tools.nlah_parser import NlahParseError, parse_nlah_dir
from meta_harness.tools.regression_flagger import flag_regressions
from meta_harness.tools.scorecard_delta import compute_batch_deltas

_LOG = logging.getLogger(__name__)

_REPORT_FILENAME = "meta_harness_report.md"
_SCORECARD_ENTITY_TYPE = "agent_scorecard"


class NlahDirResolver(Protocol):
    """Maps an ``agent_id`` to its NLAH directory under the workspace."""

    def __call__(self, agent_id: str) -> Path: ...


def default_nlah_dir_resolver(workspace_root: Path) -> NlahDirResolver:
    """Workspace-convention resolver: ``packages/agents/<kebab>/src/<snake>/nlah``."""

    def _resolve(agent_id: str) -> Path:
        dirname = agent_id.replace("_", "-")
        return workspace_root / "packages" / "agents" / dirname / "src" / agent_id / "nlah"

    return _resolve


async def run(
    *,
    customer_id: str,
    run_id: str,
    workspace_root: Path,
    semantic_store: SemanticStore | None = None,
    llm_provider: LLMProvider | None = None,
    ab_variant_a: Path | None = None,
    ab_variant_b: Path | None = None,
    ab_target_agent: str | None = None,
    nlah_dir_resolver: NlahDirResolver | None = None,
    cases_resolver: CasesRootResolver | None = None,
    agent_filter: frozenset[str] = frozenset(),
    audit_chain_loader: AuditChainLoader | None = None,
    eval_runner_loader: EvalRunnerLoader | None = None,
) -> MetaHarnessReport:
    """Run the 8-stage Meta-Harness pipeline end-to-end.

    v0.2 adds two skill-lifecycle stages (6 + 7) between REPORT (5)
    and HANDOFF (renamed to 8). The new stages are skipped when any
    of ``llm_provider``, ``audit_chain_loader``, ``eval_runner_loader``
    is ``None`` — the report's ``skill_lifecycle`` field becomes the
    empty default and the run produces v0.1-equivalent output.
    """
    nlah_resolver = nlah_dir_resolver or default_nlah_dir_resolver(workspace_root)
    cases_root = cases_resolver or default_cases_root(workspace_root)
    started_at = datetime.now(UTC)

    # Stage 2: BATCH_EVAL (we need the scorecards to also drive the
    # INTROSPECT loop's agent_id set; running BATCH_EVAL first +
    # introspecting the same set keeps the two stages consistent).
    batch_runner = BatchEvalRunner(
        cases_root=cases_root,
        config=BatchEvalConfig(agent_filter=agent_filter, llm_provider=llm_provider),
    )
    scorecards = await batch_runner.run_batch(customer_id=customer_id, run_id=run_id)

    # Stage 1: INTROSPECT — best-effort. NlahParseError surfaces in
    # the report's manifest section as an "(introspection failed)"
    # marker; the run continues.
    manifests = _introspect_agents(
        scorecards=scorecards,
        nlah_resolver=nlah_resolver,
        cases_root=cases_root,
    )

    # Stage 3: AB_COMPARE (optional).
    ab_result = await _maybe_ab_compare(
        customer_id=customer_id,
        run_id=run_id,
        ab_variant_a=ab_variant_a,
        ab_variant_b=ab_variant_b,
        ab_target_agent=ab_target_agent,
        cases_resolver=cases_root,
        llm_provider=llm_provider,
    )

    # Stage 4: DELTA.
    previous_scorecards = await _fetch_previous_scorecards(
        semantic_store=semantic_store,
        customer_id=customer_id,
        current_run_id=run_id,
    )
    deltas = compute_batch_deltas(scorecards, previous_scorecards)

    # Stage 5: REPORT (assembly only — final report constructed after
    # Stages 6 + 7 so skill_lifecycle is populated).
    regressions = flag_regressions(deltas)

    # Stage 6 SKILL_TRIGGER + Stage 7 SKILL_CREATE (v0.2). Returns the
    # empty summary when any of the lifecycle inputs is None —
    # v0.1-equivalent backwards-compat shape.
    skill_lifecycle: SkillLifecycleSummary = await run_skill_lifecycle(
        scorecards=scorecards,
        customer_id=customer_id,
        run_id=run_id,
        workspace_root=workspace_root,
        cases_resolver=cases_root,
        audit_chain_loader=audit_chain_loader,
        llm_provider=llm_provider,
        eval_runner_loader=eval_runner_loader,
    )

    completed_at = datetime.now(UTC)
    report = MetaHarnessReport(
        customer_id=customer_id,
        run_id=run_id,
        scan_started_at=started_at,
        scan_completed_at=completed_at,
        manifests=tuple(manifests),
        scorecards=tuple(scorecards),
        scorecard_deltas=deltas,
        regressions_flagged=regressions,
        ab_comparison=ab_result,
        skill_lifecycle=skill_lifecycle,
    )

    # Stage 8 HANDOFF (renamed from v0.1 Stage 6).
    await _handoff(
        report=report,
        workspace_root=workspace_root,
        semantic_store=semantic_store,
    )
    return report


def _introspect_agents(
    *,
    scorecards: list[Scorecard],
    nlah_resolver: NlahDirResolver,
    cases_root: CasesRootResolver,
) -> list[AgentManifest]:
    """Parse each evaluated agent's NLAH directory. Best-effort."""
    manifests: list[AgentManifest] = []
    for sc in scorecards:
        nlah_dir = nlah_resolver(sc.agent_id)
        try:
            manifest = parse_nlah_dir(
                nlah_dir,
                agent_id=sc.agent_id,
                eval_cases_dir=cases_root(sc.agent_id),
            )
        except NlahParseError as exc:
            _LOG.warning(
                "INTROSPECT skipped agent_id=%s nlah_dir=%s: %s",
                sc.agent_id,
                nlah_dir,
                exc,
            )
            continue
        manifests.append(manifest)
    return manifests


async def _maybe_ab_compare(
    *,
    customer_id: str,
    run_id: str,
    ab_variant_a: Path | None,
    ab_variant_b: Path | None,
    ab_target_agent: str | None,
    cases_resolver: CasesRootResolver,
    llm_provider: LLMProvider | None,
) -> ABComparison | None:
    """Run A/B compare when all three A/B inputs are present.

    Partial-input (only one or two of the three set) is treated as
    operator error and raises ``ValueError`` so the CLI can surface
    a clear message before the run starts.
    """
    have_any = any(v is not None for v in (ab_variant_a, ab_variant_b, ab_target_agent))
    have_all = all(v is not None for v in (ab_variant_a, ab_variant_b, ab_target_agent))
    if not have_any:
        return None
    if not have_all:
        raise ValueError(
            "A/B compare requires all three of ab_variant_a, ab_variant_b, "
            "and ab_target_agent — partial inputs are operator error."
        )
    assert ab_variant_a is not None  # noqa: S101
    assert ab_variant_b is not None  # noqa: S101
    assert ab_target_agent is not None  # noqa: S101

    request = ABCompareRequest(
        customer_id=customer_id,
        run_id=run_id,
        agent_id=ab_target_agent,
        variant_a_path=ab_variant_a,
        variant_b_path=ab_variant_b,
        llm_provider=llm_provider,
    )
    return await ab_compare(request, cases_resolver=cases_resolver)


async def _fetch_previous_scorecards(
    *,
    semantic_store: SemanticStore | None,
    customer_id: str,
    current_run_id: str,
) -> list[Scorecard]:
    """Load prior agent_scorecard entities (most-recent per agent_id).

    Returns an empty list when ``semantic_store`` is None (Q5
    default) — every agent shows up as a first-run delta in that
    case. When a store is provided, scans for entities with
    ``entity_type="agent_scorecard"``, groups by ``agent_id``,
    keeps the most-recent row (by ``created_at``) that is NOT
    from the current run.
    """
    if semantic_store is None:
        return []

    rows = await semantic_store.list_entities_by_type(
        tenant_id=customer_id,
        entity_type=_SCORECARD_ENTITY_TYPE,
    )
    most_recent: dict[str, EntityRow] = {}
    for row in rows:
        if row.properties.get("run_id") == current_run_id:
            continue
        agent_id = row.properties.get("agent_id")
        if not isinstance(agent_id, str):
            continue
        prior = most_recent.get(agent_id)
        if prior is None or row.created_at > prior.created_at:
            most_recent[agent_id] = row

    return [_scorecard_from_row(row) for row in most_recent.values()]


def _scorecard_from_row(row: EntityRow) -> Scorecard:
    """Rebuild a Scorecard from a SemanticStore EntityRow's properties."""
    p = row.properties
    evaluated_at_raw = p.get("evaluated_at")
    if isinstance(evaluated_at_raw, str):
        evaluated_at = datetime.fromisoformat(evaluated_at_raw)
    elif isinstance(evaluated_at_raw, datetime):
        evaluated_at = evaluated_at_raw
    else:
        evaluated_at = row.created_at

    pass_rate = p.get("pass_rate")
    error = p.get("error")

    return Scorecard(
        customer_id=str(p["customer_id"]),
        run_id=str(p["run_id"]),
        agent_id=str(p["agent_id"]),
        total_cases=int(p.get("total_cases", 0)),
        passed=int(p.get("passed", 0)),
        failed=int(p.get("failed", 0)),
        pass_rate=float(pass_rate) if pass_rate is not None else None,
        error=str(error) if error is not None else None,
        evaluated_at=evaluated_at,
    )


async def _handoff(
    *,
    report: MetaHarnessReport,
    workspace_root: Path,
    semantic_store: SemanticStore | None,
) -> None:
    """Write workspace markdown + persist KG entities (Q5 opt-in)."""
    markdown = render_report(report)
    output_path = workspace_root / _REPORT_FILENAME
    output_path.write_text(markdown, encoding="utf-8")
    _LOG.info("Stage 6 HANDOFF wrote report markdown to %s", output_path)

    scorecard_entities = tuple(_scorecard_to_entity(sc) for sc in report.scorecards)
    await upsert_scorecards(semantic_store=semantic_store, entities=scorecard_entities)

    ab_entity = _ab_to_entity(report.ab_comparison)
    await upsert_ab_result(semantic_store=semantic_store, entity=ab_entity)


def _scorecard_to_entity(sc: Scorecard) -> AgentScorecard:
    return AgentScorecard(
        customer_id=sc.customer_id,
        run_id=sc.run_id,
        agent_id=sc.agent_id,
        total_cases=sc.total_cases,
        passed=sc.passed,
        failed=sc.failed,
        pass_rate=sc.pass_rate,
        error=sc.error,
        evaluated_at=sc.evaluated_at,
    )


def _ab_to_entity(ab: ABComparison | None) -> ABComparisonResult | None:
    if ab is None:
        return None
    return ABComparisonResult(
        customer_id=ab.customer_id,
        run_id=ab.run_id,
        agent_id=ab.agent_id,
        variant_a_path=ab.variant_a_path,
        variant_b_path=ab.variant_b_path,
        variant_a_pass_rate=ab.variant_a_pass_rate,
        variant_b_pass_rate=ab.variant_b_pass_rate,
        byte_equal=ab.byte_equal,
        evaluated_at=ab.evaluated_at,
    )


__all__ = [
    "NlahDirResolver",
    "default_nlah_dir_resolver",
    "run",
]


# Re-export ScorecardDelta so the driver's public surface is self-contained
# even though deltas are only emitted via the report.
_ = ScorecardDelta
