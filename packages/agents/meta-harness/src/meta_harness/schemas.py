"""Meta-harness schemas — pydantic models for the 6-stage pipeline.

Per Q1 of the A.4 plan, the agent emits in 2 directions per run:

  1. ``SemanticStore`` entities (``entity_type="agent_scorecard"``
     per evaluated agent + ``entity_type="ab_comparison_result"``
     when the A/B subcommand is used).
  2. ``meta_harness_report.md`` workspace markdown.

**NO bus emission** (Q-ARCH-2 deferred to v0.2). **NO NLAH writes**
(Q-ARCH-1 deferred; v0.2 plan MUST review subscriber-ACL per
ADR-012 since v0.2 introduces auto-acting behavior).

This module ships the internal pydantic types that flow through the
pipeline:

  Stage 1 INTROSPECT       -> AgentManifest (per evaluated agent)
  Stage 2 BATCH_EVAL       -> Scorecard (per evaluated agent)
  Stage 3 AB_COMPARE       -> ABComparison (optional; only when
                              ``ab-compare`` subcommand used)
  Stage 4 DELTA            -> ScorecardDelta (per evaluated agent)
  Stage 5 REPORT           -> MetaHarnessReport (the assembled
                              top-level run artefact)
  Stage 6 HANDOFF          -> meta_harness_report.md + KG opt-in

**Watch-items** carried in the schema shape:

- WI-3 (stub-LLM determinism). ``ABComparison.byte_equal`` is the
  flag — under stub-LLM mode + identical NLAH, both variants MUST
  produce byte-equal ``RunOutcome`` arrays.
- WI-4 (read-only NLAH). The ``AgentManifest`` shape carries only
  parse-output fields — no path-handle that could leak a write
  surface. Task 3's parser ships the runtime guard.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Bounds that protect the schemas from runaway producer-side growth.
# A persona excerpt is a single paragraph; declared_tools is a small
# list. The eval-case caps mirror the per-agent eval suites we've
# shipped (D.13/D.12 each ship 10 cases; F.3 ships ~12).
_MAX_AGENT_ID_LENGTH = 64
_MAX_PERSONA_LENGTH = 2048
_MAX_DECLARED_TOOLS = 64
_MAX_DECLARED_TOOL_NAME_LENGTH = 128
_MAX_CASES_PER_AGENT = 256
_MAX_EXAMPLES_PER_AGENT = 64

# Pass rates are in [0, 1]; deltas are in percentage-point units
# (current_pct - previous_pct), so they range [-100, +100].
_MIN_PASS_RATE = 0.0
_MAX_PASS_RATE = 1.0
_MIN_DELTA_PCT = -100.0
_MAX_DELTA_PCT = 100.0


class AgentManifest(BaseModel):
    """Output of Stage 1 INTROSPECT for one evaluated agent.

    Task 3's ``nlah_parser`` walks each agent's NLAH directory per
    ADR-007 v1.2 conventions and produces one instance per agent.
    All fields are derived from read-only parse; no write surface.
    """

    model_config = ConfigDict(frozen=True)

    agent_id: str = Field(min_length=1, max_length=_MAX_AGENT_ID_LENGTH)
    persona: str = Field(default="", max_length=_MAX_PERSONA_LENGTH)
    declared_tools: tuple[str, ...] = Field(default_factory=tuple, max_length=_MAX_DECLARED_TOOLS)
    example_count: int = Field(ge=0, le=_MAX_EXAMPLES_PER_AGENT)
    eval_case_count: int = Field(ge=0, le=_MAX_CASES_PER_AGENT)
    nlah_dir: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def _bound_each_tool_name(self) -> AgentManifest:
        for tool in self.declared_tools:
            if not tool:
                raise ValueError("declared_tools entries must be non-empty")
            if len(tool) > _MAX_DECLARED_TOOL_NAME_LENGTH:
                raise ValueError(
                    f"declared tool name exceeds {_MAX_DECLARED_TOOL_NAME_LENGTH} chars"
                )
        return self


class Scorecard(BaseModel):
    """Output of Stage 2 BATCH_EVAL for one evaluated agent.

    XOR invariant: ``(pass_rate is None) iff (error is not None)``.
    A successful run sets ``pass_rate`` (in [0, 1]) and leaves
    ``error`` as ``None``; a failed per-agent run sets ``error`` (a
    short string) and leaves ``pass_rate`` as ``None``. Per Task 4's
    risk-mitigation row, one agent's eval failure must not poison
    the batch — failures surface as Scorecard rows with
    ``pass_rate=None`` + a populated ``error``.
    """

    model_config = ConfigDict(frozen=True)

    customer_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=_MAX_AGENT_ID_LENGTH)
    total_cases: int = Field(ge=0, le=_MAX_CASES_PER_AGENT)
    passed: int = Field(ge=0, le=_MAX_CASES_PER_AGENT)
    failed: int = Field(ge=0, le=_MAX_CASES_PER_AGENT)
    pass_rate: float | None = Field(default=None, ge=_MIN_PASS_RATE, le=_MAX_PASS_RATE)
    error: str | None = Field(default=None, max_length=512)
    evaluated_at: datetime

    @model_validator(mode="after")
    def _xor_passrate_error(self) -> Scorecard:
        if self.pass_rate is None and self.error is None:
            raise ValueError("Scorecard requires either pass_rate (success) or error (failure)")
        if self.pass_rate is not None and self.error is not None:
            raise ValueError("Scorecard cannot carry both pass_rate and error — they are XOR")
        return self

    @model_validator(mode="after")
    def _counts_sum_to_total_when_passing(self) -> Scorecard:
        if self.pass_rate is None:
            return self
        if self.passed + self.failed != self.total_cases:
            raise ValueError(
                f"passed ({self.passed}) + failed ({self.failed}) must equal "
                f"total_cases ({self.total_cases}) when scorecard reports a pass_rate"
            )
        return self


class ScorecardDelta(BaseModel):
    """Output of Stage 4 DELTA for one evaluated agent.

    Diffs the current run's Scorecard against the previous run's
    Scorecard loaded from SemanticStore (or treats prev as empty
    when no prior run exists — the ``is_first_run`` flag captures
    that case, and ``delta_pct`` is 0 by convention so first-run
    rows never count as regressions).

    ``previous_pass_rate`` and ``current_pass_rate`` may both be
    ``None`` (the prior or current per-agent run failed). The
    ``delta_pct`` field is only meaningful when both are non-None;
    callers should consult ``is_comparable`` before reading it.
    """

    model_config = ConfigDict(frozen=True)

    agent_id: str = Field(min_length=1, max_length=_MAX_AGENT_ID_LENGTH)
    previous_pass_rate: float | None = Field(default=None, ge=_MIN_PASS_RATE, le=_MAX_PASS_RATE)
    current_pass_rate: float | None = Field(default=None, ge=_MIN_PASS_RATE, le=_MAX_PASS_RATE)
    delta_pct: float = Field(ge=_MIN_DELTA_PCT, le=_MAX_DELTA_PCT)
    is_first_run: bool = False

    @model_validator(mode="after")
    def _first_run_implies_no_previous(self) -> ScorecardDelta:
        if self.is_first_run and self.previous_pass_rate is not None:
            raise ValueError("is_first_run=True requires previous_pass_rate=None")
        if self.is_first_run and self.delta_pct != 0.0:
            raise ValueError("is_first_run=True requires delta_pct=0.0")
        return self

    @property
    def is_comparable(self) -> bool:
        """True iff both previous and current pass_rate are non-None.

        ``delta_pct`` is only operator-meaningful when this is True.
        """
        return self.previous_pass_rate is not None and self.current_pass_rate is not None


class ABComparisonCaseDelta(BaseModel):
    """Per-case diff inside an ABComparison.

    Carries the case id, whether each variant passed, and a
    ``byte_equal`` flag for that single case's serialized
    RunOutcome.
    """

    model_config = ConfigDict(frozen=True)

    case_id: str = Field(min_length=1, max_length=128)
    variant_a_passed: bool
    variant_b_passed: bool
    byte_equal: bool


class ABComparison(BaseModel):
    """Output of Stage 3 AB_COMPARE for one A/B run.

    v0.1 ships single-agent A/B only — cross-agent A/B is deferred
    to A.4 v0.2. The ``byte_equal`` flag (top-level) is the WI-3
    acceptance: under stub-LLM mode + identical NLAH, both variants
    MUST produce byte-equal serialized RunOutcome arrays. Any drift
    signals a hidden non-determinism source.
    """

    model_config = ConfigDict(frozen=True)

    customer_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=_MAX_AGENT_ID_LENGTH)
    variant_a_path: str = Field(min_length=1, max_length=512)
    variant_b_path: str = Field(min_length=1, max_length=512)
    variant_a_pass_rate: float = Field(ge=_MIN_PASS_RATE, le=_MAX_PASS_RATE)
    variant_b_pass_rate: float = Field(ge=_MIN_PASS_RATE, le=_MAX_PASS_RATE)
    per_case_deltas: tuple[ABComparisonCaseDelta, ...] = Field(
        default_factory=tuple, max_length=_MAX_CASES_PER_AGENT
    )
    byte_equal: bool
    evaluated_at: datetime

    @model_validator(mode="after")
    def _variants_differ(self) -> ABComparison:
        if self.variant_a_path == self.variant_b_path:
            raise ValueError(
                "variant_a_path and variant_b_path must differ — A/B compares two variants"
            )
        return self


class RegressionFlag(BaseModel):
    """One entry in MetaHarnessReport.regressions_flagged.

    Surfaced when a ScorecardDelta crosses the v0.1 regression
    threshold (≥5% pass-rate drop). Task 7's regression_flagger
    produces these from ScorecardDelta rows.
    """

    model_config = ConfigDict(frozen=True)

    agent_id: str = Field(min_length=1, max_length=_MAX_AGENT_ID_LENGTH)
    previous_pass_rate: float = Field(ge=_MIN_PASS_RATE, le=_MAX_PASS_RATE)
    current_pass_rate: float = Field(ge=_MIN_PASS_RATE, le=_MAX_PASS_RATE)
    delta_pct: float = Field(ge=_MIN_DELTA_PCT, le=_MAX_DELTA_PCT)


class MetaHarnessReport(BaseModel):
    """Top-level run artefact emitted by Stage 5 REPORT.

    Serialised by Stage 6 HANDOFF to ``meta_harness_report.md`` +
    (opt-in) one ``agent_scorecard`` SemanticStore entity per
    evaluated agent + (when A/B subcommand used) one
    ``ab_comparison_result`` entity.

    Per Q-ARCH-2: **no bus emission**. The markdown + KG are the
    only emit directions in v0.1.
    """

    model_config = ConfigDict(frozen=True)

    customer_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(min_length=1, max_length=128)
    scan_started_at: datetime
    scan_completed_at: datetime
    manifests: tuple[AgentManifest, ...] = Field(default_factory=tuple)
    scorecards: tuple[Scorecard, ...] = Field(default_factory=tuple)
    scorecard_deltas: tuple[ScorecardDelta, ...] = Field(default_factory=tuple)
    regressions_flagged: tuple[RegressionFlag, ...] = Field(default_factory=tuple)
    ab_comparison: ABComparison | None = None
    schema_version: Literal["meta_harness.v0.1"] = "meta_harness.v0.1"

    @property
    def total_agents_evaluated(self) -> int:
        return len(self.scorecards)

    @property
    def total_regressions(self) -> int:
        return len(self.regressions_flagged)

    @property
    def successful_runs(self) -> int:
        """Scorecards with a non-None pass_rate (per-agent run did not error)."""
        return sum(1 for s in self.scorecards if s.pass_rate is not None)


__all__ = [
    "ABComparison",
    "ABComparisonCaseDelta",
    "AgentManifest",
    "MetaHarnessReport",
    "RegressionFlag",
    "Scorecard",
    "ScorecardDelta",
]
