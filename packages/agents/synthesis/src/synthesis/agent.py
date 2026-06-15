"""Synthesis Agent driver — wires the 6-stage pipeline.

Task 9 of the D.13 v0.1 plan. Mirrors D.6 / D.7 / D.8 driver shape;
the D.13 specifics:

- Three operator-pinned sibling workspaces (D.7 / D.6 / F.3) read
  forgivingly via ``read_sibling_workspaces``.
- **First agent that calls the LLM in its hot path.** Stage 3
  NARRATE produces 1 outline + N per-section + 1 exec-summary LLM
  calls through ``charter.llm.LLMProvider``.
- **Q6 retry loop.** Stage 4 REVIEW rejects on classifier-substring
  leakage; the driver re-runs NARRATE with
  ``q6_violation_retry_hint=True`` (max 1 retry per run). On
  shape-violation, the driver accepts the degraded draft and logs
  a warning (no retry — retrying probably won't help).
- Fallback narrative on `OutlineCallError` /
  `ExecutiveSummaryCallError`: emit a single-section "synthesis
  failed" report pointing at the raw sibling-workspace findings.json
  files. The audit chain still hash-chains the run.

Six-stage pipeline (per the plan):

  1. INGEST     — 3-workspace read via ``read_sibling_workspaces``.
  2. ENRICH     — ``build_context_bundle`` (Q6 first-line scrub).
  3. NARRATE    — 2-call LLM orchestration (outline + per-section
                  + exec-summary). May raise typed
                  narrator errors -> fallback narrative.
  4. REVIEW     — deterministic narrative validator + Q6 substring
                  guard. Retry on Q6 violation, accept on shape.
  5. SUMMARIZE  — assemble ``SynthesisReport``.
  6. HANDOFF    — write ``narrative.md`` + ``executive_summary.md``
                  to the charter workspace; optional
                  ``SynthesisReportEntity`` upsert via kg_writer.

**Single-tenant ``semantic_store=None`` opt-in default** per Q5.
Multi-tenant production blocks on the future SET LOCAL ``$1``
tenant-RLS substrate-fix plan.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider
from charter.memory.semantic import SemanticStore
from nexus_runtime.hermes import detect_skill_trigger, upsert_skill_candidate
from nexus_runtime.llm_invariants.bounded import assert_bounded_retry
from nexus_runtime.llm_invariants.categorical import assert_categorical_only
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope

from synthesis.context_bundle import build_context_bundle
from synthesis.entities import SynthesisReportEntity
from synthesis.kg_writer import upsert_synthesis_report
from synthesis.narrator import (
    ExecutiveSummaryCallError,
    OutlineCallError,
    SynthesisDraft,
    narrate,
)
from synthesis.ocsf.emission import SYNTHESIS_FINDING_OUTPUT, build_synthesis_finding_json
from synthesis.reviewer import RETRY_HINT_Q6, review
from synthesis.schemas import (
    ContextBundle,
    ExecutiveSummary,
    NarrativeSection,
    OutlineSection,
    ReviewVerdict,
    SynthesisOutline,
    SynthesisReport,
)
from synthesis.tools.sibling_workspace_reader import read_sibling_workspaces
from synthesis.validation.hallucination_guard import assert_findings_cited

_LOG = logging.getLogger(__name__)

DEFAULT_NLAH_VERSION = "0.1.0"
DEFAULT_MODEL_PIN = "claude-haiku-4-5-20251001"

# Q6 retry budget per run. v0.1 caps at 1 retry — if the LLM
# hallucinates Q6 substrings twice in a row, the driver accepts the
# degraded draft and surfaces the violation in the audit log so the
# operator can decide.
_Q6_RETRY_BUDGET = 1


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to the D.13 agent.

    v0.1 ships zero charter-registered tools — sibling-workspace
    reads are pure filesystem I/O (no cloud-call budget), LLM calls
    go through ``charter.llm`` directly (budget tracked via the
    provider's audit emission). v0.2 may register the prompt-template
    loader if NLAH dispatch needs it.
    """
    return ToolRegistry()


def _envelope(
    contract: ExecutionContract,
    *,
    correlation_id: str,
    model_pin: str,
) -> NexusEnvelope:
    return NexusEnvelope(
        correlation_id=correlation_id,
        tenant_id=contract.customer_id,
        agent_id="synthesis",
        nlah_version=DEFAULT_NLAH_VERSION,
        model_pin=model_pin,
        charter_invocation_id=contract.delegation_id,
    )


async def _propose_skill_candidate(
    *,
    audit_path: Path,
    semantic_store: SemanticStore,
    agent_id: str,
    run_id: str,
    tenant_id: str,
) -> None:
    """Hermes Phase 1 (C-2): propose a skill candidate from this run's audit chain.

    Reads the run's audit entries, runs the hoisted ``detect_skill_trigger`` with
    ``include_llm_stages=True`` (D.13 is LLM-stage-driven, not tool-driven), and on
    a novel-workflow hit upserts a ``skill_candidate`` entity into the SemanticStore.
    Proposer-only (C2-C): ``deployed_tool_sequence_hashes`` is empty — novelty
    adjudication + deployment are the meta-harness eval-gate's sole authority.
    """
    entries = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    trigger = detect_skill_trigger(
        agent_id=agent_id,
        run_id=run_id,
        audit_entries=entries,
        deployed_tool_sequence_hashes=frozenset(),
        include_llm_stages=True,
    )
    if trigger is None:
        return
    await upsert_skill_candidate(
        semantic_store,
        tenant_id=tenant_id,
        skill_id=f"{agent_id}:{trigger.tool_sequence_hash}",
        properties={
            "agent_id": agent_id,
            "run_id": trigger.run_id,
            "tool_sequence_hash": trigger.tool_sequence_hash,
            "tool_names": list(trigger.tool_names),
            "audit_entry_hashes": list(trigger.audit_entry_hashes),
        },
    )


async def run(
    contract: ExecutionContract,
    *,
    llm_provider: LLMProvider,
    investigation_workspace: Path | str | None = None,
    compliance_workspace: Path | str | None = None,
    cloud_posture_workspace: Path | str | None = None,
    semantic_store: SemanticStore | None = None,
    model_pin: str = DEFAULT_MODEL_PIN,
) -> SynthesisReport:
    """Run the Synthesis Agent end-to-end under the runtime charter.

    Args:
        contract: The signed ``ExecutionContract``.
        llm_provider: REQUIRED — D.13 is the first agent that calls
            the LLM in its hot path. The driver fails fast if this
            is ``None`` (no fallback to non-LLM rendering in v0.1).
        investigation_workspace: Optional path to a D.7 Investigation
            workspace. Skipped if None.
        compliance_workspace: Optional path to a D.6 Compliance
            workspace. Skipped if None.
        cloud_posture_workspace: Optional path to an F.3 Cloud
            Posture workspace. Skipped if None.
        semantic_store: Optional SemanticStore for KG writes
            (single-tenant v0.1).
        model_pin: LLM model pin (default workhorse-tier Claude).

    Returns:
        The assembled ``SynthesisReport``. Side effects: writes
        ``narrative.md`` + ``executive_summary.md`` to the charter
        workspace; optionally upserts a ``SynthesisReportEntity``
        to the SemanticStore.
    """
    registry = build_registry()
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        envelope = _envelope(contract, correlation_id=correlation_id, model_pin=model_pin)
        del envelope  # plumbed for future audit-emit; not consumed in v0.1

        # Stage 1: INGEST — 3 sibling workspaces, forgiving reader.
        sibling_findings = await read_sibling_workspaces(
            investigation_workspace=_as_path(investigation_workspace),
            compliance_workspace=_as_path(compliance_workspace),
            cloud_posture_workspace=_as_path(cloud_posture_workspace),
        )

        # Stage 2: ENRICH — Q6 first-line scrub; structured-fields-only.
        context_bundle = build_context_bundle(
            sibling_findings,
            customer_id=contract.customer_id,
            scan_window_start=contract.created_at,
            scan_window_end=datetime.now(UTC),
        )

        # Stages 3 + 4: NARRATE + REVIEW (with Q6 retry loop).
        draft, verdict, retry_count = await _narrate_and_review(
            llm_provider=llm_provider,
            context_bundle=context_bundle,
            model_pin=model_pin,
        )

        # Phase C SS5: make the bounded-retry invariant load-bearing (WI-Y10). attempts =
        # initial + retries; the loop caps retries at _Q6_RETRY_BUDGET, so a future change that
        # let the loop run away would trip the H5 bound here rather than silently overspending.
        assert_bounded_retry(retry_count + 1)

        # Stage 5: SUMMARIZE — assemble the SynthesisReport.
        scan_completed = datetime.now(UTC)
        report = _assemble_report(
            contract=contract,
            draft=draft,
            scan_started=scan_started,
            scan_completed=scan_completed,
            review_retries=retry_count,
            verdict=verdict,
        )

        # Stage 6: HANDOFF — write markdown files; optional KG upsert.
        narrative_md = _render_narrative_md(report)
        exec_summary_md = _render_executive_summary_md(report)

        # Phase C SS5: make the two LLM-output invariants load-bearing on the rendered
        # narrative, before any artifact is written. assert_categorical_only (WI-Y8) hard-blocks
        # plaintext PII/PAN leaking into the narrative or summary; assert_findings_cited (WI-Y13
        # hallucination guard) hard-blocks narrative prose that cites a finding id beyond the
        # report's validated citation set (the outline-selected ids the reviewer accepted) — so
        # an LLM that invents an id in its free text trips the guard. Validation-only — the
        # rendered bytes are unchanged, so the stub eval cases stay byte-identical (WI-Y5).
        assert_categorical_only(narrative_md)
        assert_categorical_only(exec_summary_md)
        assert_findings_cited(narrative_md, set(report.cited_finding_ids))

        ctx.write_output("narrative.md", narrative_md.encode("utf-8"))
        ctx.write_output("executive_summary.md", exec_summary_md.encode("utf-8"))
        # v0.2 Task 4 (Q1): additive OCSF 2004 emission alongside the markdown artifacts.
        # The markdown above is unchanged, so the 10 stub eval cases stay byte-identical (WI-Y5).
        ctx.write_output(SYNTHESIS_FINDING_OUTPUT, build_synthesis_finding_json(report))

        await upsert_synthesis_report(
            semantic_store=semantic_store,
            entity=SynthesisReportEntity(
                customer_id=report.customer_id,
                run_id=report.run_id,
                section_count=report.total_sections,
                executive_summary_paragraph=report.executive_summary.paragraph,
                total_cited_findings=report.total_cited_findings,
                scan_started_at=report.scan_started_at,
                scan_completed_at=report.scan_completed_at,
                review_retries=report.review_retries,
            ),
        )

        # Hermes Phase 1 (C-2): detect a novel LLM-stage workflow in this run and
        # PROPOSE it as a skill candidate. C2-C: propose-only — the meta-harness
        # eval-gate + C-1 remain the SOLE deploy authority; this agent never deploys.
        if semantic_store is not None and ctx.audit is not None:
            await _propose_skill_candidate(
                audit_path=ctx.audit.path,
                semantic_store=semantic_store,
                agent_id="synthesis",
                run_id=contract.delegation_id,
                tenant_id=contract.customer_id,
            )

        ctx.assert_complete()

    return report


# ---------------------------------------------------------------------------
# Stage 3 + 4 — NARRATE / REVIEW with Q6 retry loop
# ---------------------------------------------------------------------------


async def _narrate_and_review(
    *,
    llm_provider: LLMProvider,
    context_bundle: ContextBundle,
    model_pin: str,
) -> tuple[SynthesisDraft, ReviewVerdict, int]:
    """Drive NARRATE + REVIEW with the Q6 retry budget.

    Returns ``(draft, verdict, retry_count)``. On
    ``OutlineCallError`` / ``ExecutiveSummaryCallError`` from the
    narrator, returns a fallback draft + a synthetic failing verdict
    + zero retries. On Q6 violation, retries up to
    ``_Q6_RETRY_BUDGET`` times. On shape violation, accepts the
    degraded draft and logs a warning.
    """
    retry_count = 0
    q6_retry_hint = False

    try:
        draft = await narrate(
            llm_provider=llm_provider,
            context_bundle=context_bundle,
            model_pin=model_pin,
            q6_violation_retry_hint=q6_retry_hint,
        )
    except (OutlineCallError, ExecutiveSummaryCallError) as exc:
        _LOG.warning("narrator typed-error fallback path engaged: %s", exc)
        return _fallback_draft(context_bundle), _fallback_verdict(exc), 0

    verdict = review(draft)
    while not verdict.passed and verdict.retry_hint == RETRY_HINT_Q6:
        if retry_count >= _Q6_RETRY_BUDGET:
            _LOG.warning(
                "Q6 retry budget exhausted (%d retries); accepting degraded draft "
                "with violations=%s",
                retry_count,
                verdict.violations,
            )
            break
        retry_count += 1
        _LOG.info("Q6 retry %d/%d: re-narrating with retry hint", retry_count, _Q6_RETRY_BUDGET)
        q6_retry_hint = True
        try:
            draft = await narrate(
                llm_provider=llm_provider,
                context_bundle=context_bundle,
                model_pin=model_pin,
                q6_violation_retry_hint=q6_retry_hint,
            )
        except (OutlineCallError, ExecutiveSummaryCallError) as exc:
            _LOG.warning("narrator failure during Q6 retry; falling back: %s", exc)
            return _fallback_draft(context_bundle), _fallback_verdict(exc), retry_count
        verdict = review(draft)

    if not verdict.passed:
        _LOG.warning(
            "review failed but no further retry: hint=%s violations=%s",
            verdict.retry_hint,
            verdict.violations,
        )

    return draft, verdict, retry_count


def _fallback_draft(context_bundle: ContextBundle) -> SynthesisDraft:
    """Emit a degraded but legal SynthesisDraft when narrator fails.

    Per the plan §Risks: "narrator emits a fallback 'synthesis failed:
    see findings.json for raw data' narrative". One section pointing
    at raw sibling-workspace findings.json + a minimal executive
    summary that names the finding count.
    """
    total = context_bundle.total_findings
    fallback_intent = (
        "Synthesis narration failed; see the sibling-workspace findings.json files "
        "for raw findings."
    )
    fallback_outline = SynthesisOutline(
        sections=[
            OutlineSection(
                heading="Synthesis failed",
                intent=fallback_intent,
                cited_finding_ids=[],
            )
        ],
        overall_narrative_intent=fallback_intent,
    )
    fallback_section = NarrativeSection(
        heading="Synthesis failed",
        body=(
            "The LLM narration step failed during this run. "
            "Refer to the raw `findings.json` files in the sibling-agent workspaces "
            "(D.7 Investigation, D.6 Compliance, F.3 Cloud Posture) for the "
            f"underlying findings. Total findings observed: {total}."
        ),
        cited_finding_ids=[],
    )
    fallback_exec_summary = ExecutiveSummary(
        paragraph=(
            f"Synthesis narration failed for this run; {total} findings were "
            "observed across sibling-agent workspaces. See the raw findings.json "
            "files for details."
        ),
        key_metrics={"total_findings": total},
    )
    return SynthesisDraft(
        outline=fallback_outline,
        sections=(fallback_section,),
        executive_summary=fallback_exec_summary,
    )


def _fallback_verdict(exc: Exception) -> ReviewVerdict:
    """Synthetic verdict surfaced when narrator raises a typed error."""
    return ReviewVerdict(
        passed=False,
        retry_hint="narrator_failure",
        violations=[f"{type(exc).__name__}: {exc}"],
    )


# ---------------------------------------------------------------------------
# Stage 5 — assemble SynthesisReport
# ---------------------------------------------------------------------------


def _assemble_report(
    *,
    contract: ExecutionContract,
    draft: SynthesisDraft,
    scan_started: datetime,
    scan_completed: datetime,
    review_retries: int,
    verdict: ReviewVerdict,
) -> SynthesisReport:
    """Assemble the run-level ``SynthesisReport`` from the draft."""
    del verdict  # currently only retry_count flows in; verdict is in the audit log
    all_cited: list[str] = []
    seen: set[str] = set()
    for section in draft.sections:
        for fid in section.cited_finding_ids:
            if fid not in seen:
                seen.add(fid)
                all_cited.append(fid)

    return SynthesisReport(
        customer_id=contract.customer_id,
        run_id=contract.delegation_id,
        scan_started_at=scan_started,
        scan_completed_at=scan_completed,
        executive_summary=draft.executive_summary,
        sections=list(draft.sections),
        cited_finding_ids=all_cited,
        review_retries=review_retries,
    )


# ---------------------------------------------------------------------------
# Stage 6 — markdown rendering
# ---------------------------------------------------------------------------


def _render_narrative_md(report: SynthesisReport) -> str:
    """Render the full narrative as markdown."""
    lines: list[str] = []
    lines.append(f"# Synthesis Narrative — {report.customer_id}")
    lines.append("")
    lines.append(
        f"_Scan window: {report.scan_started_at.isoformat()} → "
        f"{report.scan_completed_at.isoformat()}_"
    )
    lines.append(f"_Run ID: `{report.run_id}`_")
    lines.append("")
    for section in report.sections:
        lines.append(f"## {section.heading}")
        lines.append("")
        lines.append(section.body)
        lines.append("")
        if section.cited_finding_ids:
            cited = ", ".join(f"`{fid}`" for fid in section.cited_finding_ids)
            lines.append(f"_Cited findings: {cited}_")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_executive_summary_md(report: SynthesisReport) -> str:
    """Render the executive summary as a standalone markdown file."""
    lines: list[str] = []
    lines.append(f"# Executive Summary — {report.customer_id}")
    lines.append("")
    lines.append(
        f"_Scan window: {report.scan_started_at.isoformat()} → "
        f"{report.scan_completed_at.isoformat()}_"
    )
    lines.append(f"_Run ID: `{report.run_id}`_")
    lines.append("")
    lines.append(report.executive_summary.paragraph)
    lines.append("")
    if report.executive_summary.key_metrics:
        lines.append("## Key Metrics")
        lines.append("")
        for key, value in report.executive_summary.key_metrics.items():
            lines.append(f"- **{key}**: {value}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _as_path(value: Path | str | None) -> Path | None:
    if value is None:
        return None
    return Path(value)


__all__ = ["DEFAULT_MODEL_PIN", "build_registry", "run"]
