"""Coverage-gap citation invariant — code-level (curiosity v0.2 Task 14, WI-X11).

**Inherited + adapted** from the D.13 hallucination guard (Cycle 13 ``assert_findings_cited``,
extended by D.7 Cycle 14 ``assert_evidence_chain``). D.13 requires a narrative to cite only real
finding ids; D.7 requires a hypothesis's evidence_refs to resolve; **D.12 requires a hypothesis to
cite a coverage_gap that was actually DETECTED** — a generative agent must ground every proposal
in a real gap, never invent one. ``assert_coverage_gap_cited`` raises if the hypothesis's cited
gap id is absent from the detected-gap set (the hallucination guard for a generative agent).
"""

from __future__ import annotations

from collections.abc import Iterable

from curiosity.ocsf.claim_translator import coverage_gap_id
from curiosity.schemas import CoverageGap, Hypothesis


class CoverageGapCitationViolationError(RuntimeError):
    """Raised when a hypothesis cites a coverage gap that was never detected (WI-X11)."""


def detected_gap_ids(gaps: Iterable[CoverageGap]) -> set[str]:
    """The coverage_gap_id set for a run's detected gaps (the citation allowlist)."""
    return {coverage_gap_id(gap) for gap in gaps}


def assert_coverage_gap_cited(hypothesis: Hypothesis, detected: set[str]) -> None:
    """Hard guard — raise if the hypothesis's cited gap was not actually detected (H... WI-X11).

    A generative hypothesis must rest on a real, detected coverage gap; a fabricated or
    mismatched citation raises before the claim is published.
    """
    cited = coverage_gap_id(hypothesis.cited_gap)
    if cited not in detected:
        raise CoverageGapCitationViolationError(
            f"Hypothesis cites coverage gap {cited!r}, which was not in the detected set "
            f"{sorted(detected)}; a generative hypothesis must ground in a real gap (WI-X11)."
        )
