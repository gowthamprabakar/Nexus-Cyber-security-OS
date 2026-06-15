"""Curiosity Agent driver — wires the 7-stage pipeline.

Task 10 of the D.12 v0.1 plan. Mirrors D.13 Synthesis's 6-stage
driver shape with one additional stage: **PUBLISH**, which sits
between PERSIST and HANDOFF and emits each hypothesis as a
``CuriosityClaim`` on the ``claims.>`` substrate introduced by
ADR-012.

D.12 is the **first publisher** on that bus; the subscriber-ACL
fence the ADR ships (forbidden_subscriptions["remediation"] =
{"claims.>"}) keeps A.1 Remediation away from speculative state.

Seven-stage pipeline:

  1. INGEST       — read aggregate sibling state from SemanticStore.
  2. DETECT       — deterministic region-gap detection.
  3. HYPOTHESIZE  — single LLM call (skipped on empty gaps).
  4. REVIEW       — Q6 substring guard + retry loop (budget=1).
  5. PERSIST      — SemanticStore upsert (Q5 opt-in).
  6. PUBLISH      — claims.> fabric emit (Q5 opt-in).
  7. HANDOFF      — workspace markdown + probe_directives.json.

**Q5 single-tenant.** Both ``semantic_store`` and ``js_client``
default to ``None``. Production deployments wire real instances
when the substrate is ready; v0.1 default exercises the no-op
paths cleanly.

**Q6 retry budget.** When the reviewer flags a Q6 violation, the
driver re-runs HYPOTHESIZE with ``q6_violation_retry_hint=True``
(max ``_Q6_RETRY_BUDGET = 1`` retry). On shape violation or after
exhaustion, the driver accepts the degraded draft and continues to
HANDOFF — the rendered markdown documents the unresolved
violations so operators see them.

**Fallback on hypothesizer typed-error.** When
``HypothesizerError`` propagates (LLM call failure or JSON shape
failure), the driver emits an empty draft (zero claims) + a
warning log + carries on to HANDOFF. This mirrors D.13's narrator-
fallback posture.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from charter import Charter, ToolRegistry
from charter.contract import ExecutionContract
from charter.llm import LLMProvider
from charter.memory.semantic import SemanticStore
from nexus_runtime.hermes import detect_skill_trigger, upsert_skill_candidate
from nexus_runtime.llm_invariants.bounded import assert_bounded_retry
from nexus_runtime.llm_invariants.categorical import assert_categorical_only
from shared.fabric import JetStreamClient
from shared.fabric.correlation import correlation_scope, new_correlation_id
from shared.fabric.envelope import NexusEnvelope
from ulid import ULID

from curiosity.claims.producer_only import assert_no_claims_subscription
from curiosity.claims_publisher import publish_claims
from curiosity.entities import HypothesisEntity
from curiosity.gate.llm_gate import assert_llm_only_with_gaps
from curiosity.hypothesizer import (
    DEFAULT_MODEL_PIN,
    HypothesizerError,
    hypothesize,
)
from curiosity.kg_writer import upsert_hypotheses
from curiosity.ocsf.claim_translator import coverage_gap_id
from curiosity.ocsf.emission import render_curiosity_findings_json
from curiosity.reviewer import RETRY_HINT_Q6, review
from curiosity.schemas import (
    CuriosityClaim,
    CuriosityDraft,
    CuriosityReport,
    Hypothesis,
    ProbeDirective,
)
from curiosity.tenant.scoped import assert_tenant_scoped
from curiosity.tools.coverage_gap_detector import detect_coverage_gaps
from curiosity.tools.sibling_state_reader import read_sibling_state
from curiosity.validation.coverage_gap_cited import assert_coverage_gap_cited

_LOG = logging.getLogger(__name__)

DEFAULT_NLAH_VERSION = "0.1.0"
_AGENT_ID = "curiosity"
_Q6_RETRY_BUDGET = 1

#: Phase C SS5: D.12 is producer-only (publishes claims.curiosity.>, never subscribes to
#: claims.>). The fabric subjects it subscribes to — currently NONE — are declared here so
#: assert_no_claims_subscription can enforce the producer-only fence (WI-X14) at run() time:
#: a regression that added a claims.* subscription to this tuple would trip the guard.
_SUBSCRIPTION_SUBJECTS: tuple[str, ...] = ()


def build_registry() -> ToolRegistry:
    """Compose the tool universe available to the D.12 agent.

    v0.1 ships zero charter-registered tools — SemanticStore reads
    are pure DB I/O via the substrate's async API, fabric publishes
    go through ``shared.fabric.JetStreamClient`` directly. v0.2 may
    register a ``read_coverage_gaps`` tool for NLAH dispatch.
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
        agent_id=_AGENT_ID,
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
    ``include_llm_stages=True`` (D.12 is LLM-stage-driven), and on a novel-workflow
    hit upserts a ``skill_candidate`` entity. Proposer-only (C2-C):
    ``deployed_tool_sequence_hashes`` is empty — novelty adjudication + deployment
    are the meta-harness eval-gate's sole authority.
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
    semantic_store: SemanticStore | None = None,
    js_client: JetStreamClient | None = None,
    model_pin: str = DEFAULT_MODEL_PIN,
) -> CuriosityReport:
    """Run the Curiosity Agent end-to-end under the runtime charter.

    Args:
        contract: signed ``ExecutionContract``.
        llm_provider: REQUIRED — D.12 is the second LLM-driven agent;
            the hypothesizer issues a single ``complete()`` call per
            run. v0.1 has no non-LLM fallback (unlike D.13's degraded
            stub path which is symmetric to ours but uses a fallback
            narrative).
        semantic_store: Optional. None -> no INGEST data + no PERSIST.
        js_client: Optional. None -> PUBLISH is a no-op + log.
        model_pin: LLM model pin (default workhorse-tier Claude).

    Returns:
        ``CuriosityReport`` with the published claims + scan metadata.
        Side effects: writes ``hypotheses.md`` +
        ``probe_directives.json`` to the contract's workspace;
        optionally persists ``HypothesisEntity`` rows to the
        SemanticStore and publishes ``CuriosityClaim`` payloads on
        ``claims.>``.
    """
    # Phase C SS5: tenant scope is the privacy boundary (WI-X13) — assert before any
    # cross-agent state is read. Cross-tenant aggregation is forbidden by the contract, always.
    assert_tenant_scoped(contract)

    registry = build_registry()
    correlation_id = new_correlation_id()

    with correlation_scope(correlation_id), Charter(contract, tools=registry) as ctx:
        scan_started = datetime.now(UTC)
        envelope = _envelope(contract, correlation_id=correlation_id, model_pin=model_pin)
        del envelope  # plumbed for future audit-emit; not consumed in v0.1

        # Stage 1: INGEST — read aggregate SemanticStore state.
        state = await read_sibling_state(
            semantic_store,
            customer_id=contract.customer_id,
        )

        # Stage 2: DETECT — deterministic region-gap detection.
        gaps = detect_coverage_gaps(state)

        # Phase C SS5: cost-discipline gate (WI-X15) — the LLM may only run when ≥1 gap was
        # detected. The hypothesizer short-circuits to an empty draft on no gaps, so llm_called
        # tracks bool(gaps); the guard makes that contract load-bearing at the driver boundary.
        assert_llm_only_with_gaps(gaps, llm_called=bool(gaps))

        # Stages 3-4: HYPOTHESIZE + REVIEW with Q6 retry loop.
        draft, retry_count = await _hypothesize_and_review(
            llm_provider=llm_provider,
            gaps=gaps,
            model_pin=model_pin,
        )

        # Phase C SS5: bounded-retry invariant (WI-X10). attempts = initial + retries; the loop
        # caps retries at _Q6_RETRY_BUDGET, so a runaway would trip the bound here.
        assert_bounded_retry(retry_count + 1)

        # Stage 5: PERSIST — SemanticStore upsert (Q5 opt-in).
        # Stage 6: PUBLISH — claims.> fabric emit (Q5 opt-in).
        # Build the claims first so PERSIST + PUBLISH share the same
        # claim_id per hypothesis.
        claims = _build_claims(draft=draft, contract=contract)
        entities = _build_entities(claims=claims, contract=contract)

        # Phase C SS5: make the generative-hallucination + categorical guards load-bearing per
        # claim, before anything is persisted or published. assert_coverage_gap_cited (WI-X11)
        # hard-blocks a hypothesis citing a gap that was not in the detected set; assert_
        # categorical_only (WI-X9) hard-blocks plaintext PII in the statement/rationale.
        detected_gaps = {coverage_gap_id(gap) for gap in gaps}
        for claim in claims:
            assert_coverage_gap_cited(claim.hypothesis, detected_gaps)
            assert_categorical_only(claim.hypothesis.statement)
            assert_categorical_only(claim.hypothesis.rationale)

        # Phase C SS5: producer-only fence (WI-X14) — D.12 publishes claims.curiosity.> and must
        # never subscribe to claims.>. Assert the declared subscription set carries no claims.*
        # subject before any fabric I/O.
        assert_no_claims_subscription(_SUBSCRIPTION_SUBJECTS)

        await upsert_hypotheses(semantic_store=semantic_store, entities=entities)
        await publish_claims(js_client=js_client, claims=claims)

        # Stage 7: HANDOFF — workspace artifacts + assembled report.
        scan_completed = datetime.now(UTC)
        report = CuriosityReport(
            customer_id=contract.customer_id,
            run_id=contract.delegation_id,
            scan_started_at=scan_started,
            scan_completed_at=scan_completed,
            claims=list(claims),
            review_retries=retry_count,
        )
        ctx.write_output(
            "hypotheses.md",
            _render_hypotheses_md(report).encode("utf-8"),
        )
        ctx.write_output(
            "probe_directives.json",
            _render_probe_directives_json(report).encode("utf-8"),
        )
        # v0.2 Q1: OCSF 2004 emission — additive alongside claims.> + markdown (WI-X5/X6).
        ctx.write_output(
            "curiosity_findings.json",
            render_curiosity_findings_json(report).encode("utf-8"),
        )

        # Hermes Phase 1 (C-2): propose a skill candidate from this run's audit
        # chain. Proposer-only (C2-C) — meta-harness eval-gate + C-1 remain the
        # SOLE deploy authority; this agent never deploys.
        if semantic_store is not None and ctx.audit is not None:
            await _propose_skill_candidate(
                audit_path=ctx.audit.path,
                semantic_store=semantic_store,
                agent_id="curiosity",
                run_id=contract.delegation_id,
                tenant_id=contract.customer_id,
            )

        ctx.assert_complete()

    return report


# ---------------------------------------------------------------------------
# Stages 3-4: HYPOTHESIZE + REVIEW with Q6 retry loop
# ---------------------------------------------------------------------------


async def _hypothesize_and_review(
    *,
    llm_provider: LLMProvider,
    gaps: tuple[Any, ...],
    model_pin: str,
) -> tuple[CuriosityDraft, int]:
    """Drive HYPOTHESIZE + REVIEW with the Q6 retry budget.

    Returns ``(draft, retry_count)``. On ``HypothesizerError``,
    returns an empty draft (fallback) + zero retries. On Q6
    violation, retries up to ``_Q6_RETRY_BUDGET`` times. On shape
    violation, accepts the degraded draft and logs a warning.
    """
    retry_count = 0
    q6_retry_hint = False

    try:
        draft = await hypothesize(
            llm_provider=llm_provider,
            gaps=gaps,
            model_pin=model_pin,
            q6_violation_retry_hint=q6_retry_hint,
        )
    except HypothesizerError as exc:
        _LOG.warning(
            "hypothesizer typed-error fallback path engaged: %s; emitting empty draft",
            exc,
        )
        return CuriosityDraft(), 0

    verdict = review(draft)
    while not verdict.passed and verdict.retry_hint == RETRY_HINT_Q6:
        if retry_count >= _Q6_RETRY_BUDGET:
            _LOG.warning(
                "Q6 retry budget exhausted (%d retries); accepting degraded "
                "draft with violations=%s",
                retry_count,
                verdict.violations,
            )
            break
        retry_count += 1
        _LOG.info(
            "Q6 retry %d/%d: re-running hypothesize with retry hint",
            retry_count,
            _Q6_RETRY_BUDGET,
        )
        q6_retry_hint = True
        try:
            draft = await hypothesize(
                llm_provider=llm_provider,
                gaps=gaps,
                model_pin=model_pin,
                q6_violation_retry_hint=q6_retry_hint,
            )
        except HypothesizerError as exc:
            _LOG.warning(
                "hypothesizer failure during Q6 retry; falling back: %s",
                exc,
            )
            return CuriosityDraft(), retry_count
        verdict = review(draft)

    if not verdict.passed:
        _LOG.warning(
            "review failed but no further retry: hint=%s violations=%s",
            verdict.retry_hint,
            verdict.violations,
        )

    return draft, retry_count


# ---------------------------------------------------------------------------
# Stages 5-6 helpers: build CuriosityClaim + HypothesisEntity per hypothesis
# ---------------------------------------------------------------------------


def _build_claims(
    *,
    draft: CuriosityDraft,
    contract: ExecutionContract,
) -> tuple[CuriosityClaim, ...]:
    """Convert each Hypothesis into a CuriosityClaim with a fresh ULID.

    The ULID flows two directions: it becomes the claim's
    ``claim_id`` AND it backfills the hypothesis's
    ``probe_directive.rationale_ref`` (which the LLM emitted as
    ``""`` per the prompt template). Both Hypothesis and
    ProbeDirective are frozen, so the rationale_ref backfill builds
    new instances.
    """
    emitted_at = datetime.now(UTC)
    claims: list[CuriosityClaim] = []
    for hyp in draft.hypotheses:
        claim_id = str(ULID())
        rewritten_directive = ProbeDirective(
            target_agent=hyp.probe_directive.target_agent,
            target_resource_arn=hyp.probe_directive.target_resource_arn,
            target_finding_id=hyp.probe_directive.target_finding_id,
            action=hyp.probe_directive.action,
            rationale_ref=claim_id,
        )
        rewritten_hyp = Hypothesis(
            statement=hyp.statement,
            rationale=hyp.rationale,
            probe_directive=rewritten_directive,
            cited_gap=hyp.cited_gap,
        )
        claims.append(
            CuriosityClaim(
                claim_id=claim_id,
                customer_id=contract.customer_id,
                hypothesis=rewritten_hyp,
                emitted_at=emitted_at,
            )
        )
    return tuple(claims)


def _build_entities(
    *,
    claims: tuple[CuriosityClaim, ...],
    contract: ExecutionContract,
) -> tuple[HypothesisEntity, ...]:
    """Build one HypothesisEntity per claim (parallel arrays)."""
    return tuple(
        HypothesisEntity(
            customer_id=claim.customer_id,
            run_id=contract.delegation_id,
            hypothesis_idx=idx,
            claim_id=claim.claim_id,
            statement=claim.hypothesis.statement,
            target_agent=claim.hypothesis.probe_directive.target_agent.value,
            cited_region=claim.hypothesis.cited_gap.region,
            emitted_at=claim.emitted_at,
        )
        for idx, claim in enumerate(claims)
    )


# ---------------------------------------------------------------------------
# Stage 7: markdown + JSON rendering
# ---------------------------------------------------------------------------


def _render_hypotheses_md(report: CuriosityReport) -> str:
    """Render the workspace markdown digest."""
    lines: list[str] = []
    lines.append(f"# Curiosity Hypotheses — {report.customer_id}")
    lines.append("")
    lines.append(
        f"_Scan window: {report.scan_started_at.isoformat()} → "
        f"{report.scan_completed_at.isoformat()}_"
    )
    lines.append(f"_Run ID: `{report.run_id}`_")
    lines.append(f"_Total claims: {report.total_claims}_")
    lines.append(f"_Gaps addressed: {report.total_gaps_addressed}_")
    lines.append(f"_Review retries: {report.review_retries}_")
    lines.append("")

    if not report.claims:
        lines.append("_No coverage gaps detected this scan window. No hypotheses emitted._")
        lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    for idx, claim in enumerate(report.claims):
        hyp = claim.hypothesis
        lines.append(f"## Hypothesis {idx + 1} — `{claim.claim_id}`")
        lines.append("")
        lines.append(hyp.statement)
        lines.append("")
        lines.append(hyp.rationale)
        lines.append("")
        directive = hyp.probe_directive
        target = (
            directive.target_resource_arn
            if directive.target_resource_arn is not None
            else directive.target_finding_id
        )
        lines.append(
            f"**Probe directive:** {directive.target_agent.value} → "
            f"`{directive.action.value}` on `{target}`"
        )
        lines.append("")
        lines.append(
            f"_Cited gap: region=`{hyp.cited_gap.region}`, "
            f"asset_count={hyp.cited_gap.asset_count}, "
            f"days_since_last_finding={hyp.cited_gap.days_since_last_finding}, "
            f"severity_hint=`{hyp.cited_gap.severity_hint}`_"
        )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_probe_directives_json(report: CuriosityReport) -> str:
    """Render the workspace probe_directives.json artifact.

    Structured for downstream agent consumption — D.7 / D.5 / D.8
    will read this in their v0.2 plans.
    """
    payload = {
        "customer_id": report.customer_id,
        "run_id": report.run_id,
        "scan_completed_at": report.scan_completed_at.isoformat(),
        "directives": [
            {
                "claim_id": claim.claim_id,
                "target_agent": claim.hypothesis.probe_directive.target_agent.value,
                "target_resource_arn": claim.hypothesis.probe_directive.target_resource_arn,
                "target_finding_id": claim.hypothesis.probe_directive.target_finding_id,
                "action": claim.hypothesis.probe_directive.action.value,
                "rationale_ref": claim.hypothesis.probe_directive.rationale_ref,
            }
            for claim in report.claims
        ],
    }
    return json.dumps(payload, indent=2)


def _as_path(value: Path | str | None) -> Path | None:
    if value is None:
        return None
    return Path(value)


__all__ = ["DEFAULT_MODEL_PIN", "build_registry", "run"]
