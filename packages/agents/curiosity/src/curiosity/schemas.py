"""Curiosity schemas — pydantic models for the proactive-hypothesis pipeline.

Per Q1 of the D.12 plan, the agent emits in 3 directions per run:

  1. ``SemanticStore`` entity (``entity_type="hypothesis"``).
  2. ``claims.>`` fabric publish on
     ``claims.tenant.<tid>.agent.curiosity``.
  3. ``hypotheses.md`` workspace markdown.

This module ships the internal pydantic types that flow through the
pipeline:

  Stage 1 INGEST       -> (uses sibling-state-reader output dicts)
  Stage 2 DETECT       -> CoverageGap (deterministic gap detector output)
  Stage 3 HYPOTHESIZE  -> CuriosityDraft (Hypothesis[] + LLM accounting)
  Stage 4 REVIEW       -> ReviewVerdict (reused from D.13 via import)
  Stage 5 PERSIST      -> HypothesisEntity (Task 8 SemanticStore writer)
  Stage 6 PUBLISH      -> CuriosityClaim (the nexus_claim envelope on
                          claims.>; payload schema for Task 9)
  Stage 7 HANDOFF      -> CuriosityReport (the full run artefact;
                          Task 10 driver serialises this + the per-
                          claim envelopes to the workspace)

**No OCSF re-export** per Q1 — the ``claims.>`` payload is a
lightweight ``nexus_claim`` envelope, NOT an OCSF event. OCSF for
claims is deferred to v0.2 pending a ``class_uid`` ADR (see
ADR-012's "Wire format" section).

**Q6 invariant (carried through from D.5 + D.13).** None of these
models carry classifier-matched substrings. The Hypothesis text +
ProbeDirective rationale are subject to D.13's reviewer
(``synthesis.reviewer._scan_classifier_labels``) in Stage 4; the
schemas themselves are typed containers.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from ulid import ULID

# Per-run caps. v0.1's region-gap detector is conservative; in
# practice it surfaces 1-3 gaps per scan window. Cap at 5 to keep the
# LLM context budget bounded + the workspace artefact scannable.
_MAX_HYPOTHESES_PER_RUN = 5
_MAX_STATEMENT_LENGTH = 400
_MAX_RATIONALE_LENGTH = 1500

# Lower bound on coverage-gap detector thresholds. Used by Task 4's
# detector for the "≥10 assets + zero findings in 30d" rule; surfaced
# here so the schema can validate detector output is internally
# consistent (no asset_count < 0, no negative day deltas).
_MIN_GAP_ASSET_COUNT = 0
_MIN_GAP_DAYS = 0


class TargetAgent(StrEnum):
    """The 3 D-track agents D.12 can address probe directives at.

    Per Q4, v0.1 is producer-only — D.7 / D.5 / D.8 consumer wire-up
    lands in those agents' v0.2 plans. The enum constraint here
    prevents drift on the producer side.
    """

    INVESTIGATION = "investigation"
    DATA_SECURITY = "data_security"
    THREAT_INTEL = "threat_intel"


class ProbeAction(StrEnum):
    """What the target agent should do with the directive.

    Matches the action the receiving agent's CLI exposes:

    - ``scan``: D.5 — re-classify a bucket / re-scan a region.
    - ``investigate``: D.7 — open an investigation around a finding.
    - ``enrich``: D.8 — pull threat-intel for a CVE / IOC.
    """

    SCAN = "scan"
    INVESTIGATE = "investigate"
    ENRICH = "enrich"


class CoverageGap(BaseModel):
    """Deterministic output of Stage 2 DETECT.

    Currently shipped: **region-gap** detector (≥10 assets + zero
    findings in 30d). v0.2 adds asset-type / time-window / severity-
    distribution / classifier-label / control-coverage gap shapes.
    """

    model_config = ConfigDict(frozen=True)

    region: str = Field(min_length=1, max_length=64)
    asset_count: int = Field(ge=_MIN_GAP_ASSET_COUNT)
    days_since_last_finding: int = Field(ge=_MIN_GAP_DAYS)
    severity_hint: str = Field(min_length=1, max_length=32)


class ProbeDirective(BaseModel):
    """One actionable directive a hypothesis emits.

    Targets exactly ONE of ``target_resource_arn`` or
    ``target_finding_id`` — never both, never neither. The
    ``rationale_ref`` links back to the parent ``CuriosityClaim``
    via its ULID ``claim_id`` so consumers can fetch context.
    """

    model_config = ConfigDict(frozen=True)

    target_agent: TargetAgent
    target_resource_arn: str | None = Field(default=None, min_length=1, max_length=256)
    target_finding_id: str | None = Field(default=None, min_length=1, max_length=128)
    action: ProbeAction
    # ``rationale_ref`` carries the parent claim_id. The LLM emits it
    # as ``""`` (template-instructed) and the driver populates with
    # the freshly-minted ULID before the claim is published. Empty
    # string is the legal "pending driver fill" state.
    rationale_ref: str = Field(default="", max_length=64)

    @model_validator(mode="after")
    def _exactly_one_target(self) -> ProbeDirective:
        if self.target_resource_arn is None and self.target_finding_id is None:
            raise ValueError(
                "ProbeDirective must set exactly one of target_resource_arn or target_finding_id"
            )
        if self.target_resource_arn is not None and self.target_finding_id is not None:
            raise ValueError(
                "ProbeDirective must set exactly one of "
                "target_resource_arn or target_finding_id (got both)"
            )
        return self


class Hypothesis(BaseModel):
    """One LLM-generated proposal about what may be under-scanned.

    Carries:

    - ``statement``: 1-2 sentence headline of the hypothesis.
    - ``rationale``: 3-5 sentence justification grounded in the
      ``cited_gap``.
    - ``probe_directive``: structured ask for a downstream agent.
    - ``cited_gap``: the deterministic CoverageGap that triggered
      this hypothesis (back-reference for audit + LLM-grounding).

    **Q6**: ``statement`` + ``rationale`` are subject to D.13's
    reviewer in Stage 4. The reviewer's classifier-substring guard
    rejects + retries on hits.
    """

    model_config = ConfigDict(frozen=True)

    statement: str = Field(min_length=1, max_length=_MAX_STATEMENT_LENGTH)
    rationale: str = Field(min_length=1, max_length=_MAX_RATIONALE_LENGTH)
    probe_directive: ProbeDirective
    cited_gap: CoverageGap


def _validate_ulid(value: str) -> str:
    """Validate a ULID-string at pydantic-field time."""
    try:
        ULID.from_str(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"claim_id is not a valid ULID: {exc}") from exc
    return value


# Annotated ULID string type — reusable across schemas that carry
# claim_id references (today: CuriosityClaim; future: A.4 Meta-
# Harness claim-aggregator types).
UlidStr = Annotated[str, Field(min_length=26, max_length=26)]


class CuriosityClaim(BaseModel):
    """The `nexus_claim` envelope published on `claims.>`.

    Per Q1 + ADR-012 wire-format resolution: NOT OCSF; a lightweight
    JSON envelope. The payload is published as
    ``json.dumps(claim.model_dump(mode="json"))`` on
    ``claims.tenant.<tid>.agent.curiosity``.
    """

    model_config = ConfigDict(frozen=True)

    claim_id: UlidStr
    customer_id: str = Field(min_length=1, max_length=128)
    agent_id: Literal["curiosity"] = "curiosity"
    hypothesis: Hypothesis
    emitted_at: datetime

    @field_validator("claim_id")
    @classmethod
    def _claim_id_is_ulid(cls, value: str) -> str:
        return _validate_ulid(value)


class CuriosityDraft(BaseModel):
    """In-flight Stage 3 HYPOTHESIZE output (pre-review).

    Stage 4 REVIEW inspects each hypothesis's text against the Q6
    classifier-substring guard. On violation, the driver re-runs
    HYPOTHESIZE with ``q6_violation_retry_hint=True``; on pass, the
    draft is promoted to a tuple of CuriosityClaims by Stage 5.

    ``hypotheses`` is capped at ``_MAX_HYPOTHESES_PER_RUN``; the
    hypothesizer truncates LLM output that exceeds the cap.
    """

    hypotheses: tuple[Hypothesis, ...] = Field(
        default_factory=tuple, max_length=_MAX_HYPOTHESES_PER_RUN
    )
    llm_call_count: int = Field(default=0, ge=0)
    total_tokens_used: int = Field(default=0, ge=0)


class CuriosityReport(BaseModel):
    """The full assembled run artefact emitted by Stage 7 HANDOFF.

    Serialised by the agent driver (Task 10) to:

      ``hypotheses.md``         — heading + per-hypothesis prose.
      ``probe_directives.json`` — structured directive list.

    Each claim is ALSO published on ``claims.>`` (Stage 6) when a
    JetStreamClient is provided; the same payload is the source for
    the workspace markdown rendering.
    """

    customer_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    scan_started_at: datetime
    scan_completed_at: datetime
    claims: list[CuriosityClaim] = Field(default_factory=list)
    review_retries: int = Field(default=0, ge=0)

    @property
    def total_claims(self) -> int:
        return len(self.claims)

    @property
    def total_gaps_addressed(self) -> int:
        """Number of distinct CoverageGap regions cited across claims.

        A given run typically emits one hypothesis per detected gap,
        but the LLM may emit multiple hypotheses against the same
        gap (e.g. region-X scan via D.7 + region-X data classification
        via D.5). This counts distinct regions, not hypotheses.
        """
        seen = {c.hypothesis.cited_gap.region for c in self.claims}
        return len(seen)


__all__ = [
    "CoverageGap",
    "CuriosityClaim",
    "CuriosityDraft",
    "CuriosityReport",
    "Hypothesis",
    "ProbeAction",
    "ProbeDirective",
    "TargetAgent",
    "UlidStr",
]
