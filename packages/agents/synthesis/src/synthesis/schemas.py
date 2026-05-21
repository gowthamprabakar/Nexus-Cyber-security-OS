"""Synthesis schemas — pydantic models for LLM-narrated output.

Per Q1 of the D.13 plan, D.13 emits **markdown reports**, not OCSF
findings. The schemas in this module are internal pydantic types that
flow through the pipeline:

  Stage 2 ENRICH       -> ContextBundle (input to the LLM call)
  Stage 3 NARRATE (out) -> SynthesisOutline (validated outline-call JSON)
                          NarrativeSection[] (per-section narration outputs)
  Stage 4 REVIEW       -> ReviewVerdict (pass/fail + retry hint)
  Stage 5 SUMMARIZE    -> SynthesisReport (the full assembled artefact)

The agent driver (Task 9) serialises ``SynthesisReport`` to
``narrative.md`` + ``executive_summary.md`` in the charter workspace.
No OCSF emit in v0.1 (deferred to v0.2 per Q1).

**Q6 invariant (carried through from D.5).** None of these models
carry classifier-matched substrings. They reference findings by ID
+ control mapping + severity + classifier *labels* (not values).
Reviewer (Task 7) enforces this on the rendered narrative; the
schemas themselves are just typed containers.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Maximum length of a finding-id citation list per narrative section.
# Keeps the LLM context budget predictable and the rendered narrative
# scannable. v0.2 may relax this.
_MAX_CITED_PER_SECTION = 16

# Maximum number of sections the outline call may return. v0.1's
# operator-summary narratives sit at 4-6 sections; cap at 12 to keep
# the per-section narration loop bounded.
_MAX_OUTLINE_SECTIONS = 12


class ContextBundle(BaseModel):
    """The structured LLM input prepared by Stage 2 ENRICH.

    The bundle aggregates the bits of sibling-agent output that the
    narrator needs: severity counts, top-N finding-ids per source,
    control-failure summary, investigation conclusions. **Strictly
    structured fields only** — never classifier-matched substrings.
    """

    model_config = ConfigDict(frozen=True)

    customer_id: str = Field(min_length=1)
    scan_window_start: datetime
    scan_window_end: datetime
    investigation_conclusions: list[dict[str, Any]] = Field(default_factory=list)
    compliance_failures: list[dict[str, Any]] = Field(default_factory=list)
    cloud_posture_findings: list[dict[str, Any]] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    total_findings: int = 0


class OutlineSection(BaseModel):
    """One section in the outline-call structured JSON output."""

    heading: str = Field(min_length=1, max_length=120)
    intent: str = Field(min_length=1, max_length=400)
    cited_finding_ids: list[str] = Field(default_factory=list, max_length=_MAX_CITED_PER_SECTION)

    @field_validator("cited_finding_ids")
    @classmethod
    def _no_empty_ids(cls, value: list[str]) -> list[str]:
        if any(not v.strip() for v in value):
            raise ValueError("cited_finding_ids must not contain empty strings")
        return value


class SynthesisOutline(BaseModel):
    """The validated outline-call output.

    The LLM returns a JSON object matching this schema. The narrator
    (Task 6) raises ``OutlineCallError`` if the raw output doesn't
    parse against this schema.
    """

    sections: list[OutlineSection] = Field(min_length=1, max_length=_MAX_OUTLINE_SECTIONS)
    overall_narrative_intent: str = Field(min_length=1, max_length=600)


class NarrativeSection(BaseModel):
    """One rendered section in the final narrative.

    Each maps 1:1 to an outline section but carries the per-section
    LLM narration body. ``cited_finding_ids`` is preserved verbatim
    from the outline so the reviewer can verify the narrative cites
    the findings it claimed it would.
    """

    heading: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=1)
    cited_finding_ids: list[str] = Field(default_factory=list, max_length=_MAX_CITED_PER_SECTION)


class ExecutiveSummary(BaseModel):
    """C-suite-shaped digest of the synthesis run."""

    paragraph: str = Field(min_length=1, max_length=2000)
    key_metrics: dict[str, int | str] = Field(default_factory=dict)


class SynthesisReport(BaseModel):
    """The full assembled synthesis artefact emitted by Stage 5.

    Serialised to two markdown files by the agent driver:

      ``narrative.md``         -- heading + per-section body, in order.
      ``executive_summary.md`` -- the executive summary paragraph +
                                  key-metrics table.
    """

    customer_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    scan_started_at: datetime
    scan_completed_at: datetime
    executive_summary: ExecutiveSummary
    sections: list[NarrativeSection] = Field(default_factory=list)
    cited_finding_ids: list[str] = Field(default_factory=list)
    review_retries: int = Field(default=0, ge=0)

    @property
    def total_sections(self) -> int:
        return len(self.sections)

    @property
    def total_cited_findings(self) -> int:
        return len(self.cited_finding_ids)


class ReviewVerdict(BaseModel):
    """Output of Stage 4 REVIEW (Task 7).

    The reviewer either approves the narrative or rejects it with a
    typed retry hint. ``q6_violation`` is the highest-priority
    failure -- the narrator MUST retry to scrub classifier-shaped
    substrings.
    """

    model_config = ConfigDict(frozen=True)

    passed: bool
    retry_hint: str = ""
    violations: list[str] = Field(default_factory=list)


__all__ = [
    "ContextBundle",
    "ExecutiveSummary",
    "NarrativeSection",
    "OutlineSection",
    "ReviewVerdict",
    "SynthesisOutline",
    "SynthesisReport",
]
