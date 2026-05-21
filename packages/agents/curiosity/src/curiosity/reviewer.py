"""Stage 4 REVIEW — deterministic Q6 substring guard for hypotheses.

D.12's second-line scrub against classifier-substring leakage. The
first line is the prompt template's Q6 reminder block (Task 5);
this is the regex enforcement. Mirrors D.13's reviewer shape +
**reuses** ``synthesis.reviewer._scan_classifier_labels`` directly
so the two agents enforce the same Q6 contract end-to-end.

**Two layers:**

1. **Shape checks** — every hypothesis has non-empty statement +
   rationale; probe directive XOR constraint (already enforced at
   pydantic-construction time by ``ProbeDirective._exactly_one_target``,
   so this is defensive redundancy that catches future schema drift).

2. **Q6 substring guard** — scans every hypothesis's statement +
   rationale + probe-directive rationale_ref text for known
   classifier patterns (SSN, credit-card with Luhn check, AWS
   access key, JWT). Reuses D.13's
   ``_scan_classifier_labels`` so both agents share the same
   pattern set.

Pure function over ``CuriosityDraft``. No LLM, no I/O, no
module-level state. Eval case ``q6_no_classifier_substring_in_
hypothesis`` (Task 12) is the WI-2 regression probe.

**Q6 meta-invariant.** The violation strings name the classifier
label, NEVER the matched substring. Mirrors D.13's reviewer
discipline; the Q6 invariant applies to the reviewer's own audit
output too.

**Retry-hint contract** (matches D.13's reviewer):

- ``retry_hint == "q6_violation"`` -> driver re-runs ``hypothesize``
  with ``q6_violation_retry_hint=True``.
- ``retry_hint == "shape_violation"`` -> driver gives up + emits
  fallback claim.
- ``retry_hint == ""`` -> verdict passed.

**Empty draft passes.** When the gap detector returns no gaps and
the hypothesizer short-circuits, the resulting empty draft is a
legal clean run — the reviewer must not block it as a "no
hypotheses" shape violation.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from synthesis.reviewer import _scan_classifier_labels
from synthesis.schemas import ReviewVerdict

from curiosity.schemas import CuriosityDraft, Hypothesis

# Retry-hint string constants — stable contract; driver branches on
# these. Identical values to D.13's reviewer so consumers can share
# retry handling code.
RETRY_HINT_Q6: Final[str] = "q6_violation"
RETRY_HINT_SHAPE: Final[str] = "shape_violation"


def review(draft: CuriosityDraft) -> ReviewVerdict:
    """Return the deterministic verdict for ``draft``.

    Pass -> ``ReviewVerdict(passed=True)``. Fail -> ``passed=False``
    + ``retry_hint`` (q6 takes precedence over shape) + a list of
    human-readable ``violations`` strings.

    Empty drafts (no hypotheses — clean run from the empty-gaps
    short-circuit) pass cleanly; D.12 does not require at-least-
    one-hypothesis the way D.13 requires at-least-one-section.
    """
    shape_violations = list(_check_shape(draft))
    q6_violations = list(_check_q6_substrings(draft))

    all_violations = shape_violations + q6_violations
    if not all_violations:
        return ReviewVerdict(passed=True, retry_hint="", violations=[])

    retry_hint = RETRY_HINT_Q6 if q6_violations else RETRY_HINT_SHAPE
    return ReviewVerdict(
        passed=False,
        retry_hint=retry_hint,
        violations=all_violations,
    )


# ---------------------------------------------------------------------------
# Layer 1 — Shape checks
# ---------------------------------------------------------------------------


def _check_shape(draft: CuriosityDraft) -> Iterable[str]:
    """Yield shape-level violation strings for ``draft``.

    Most shape constraints are already pydantic-enforced; this layer
    is defensive redundancy that catches schema drift in future
    versions. Empty hypotheses tuple is legal.
    """
    for idx, hyp in enumerate(draft.hypotheses):
        if not hyp.statement.strip():
            yield f"hypothesis index {idx} has empty statement"
        if not hyp.rationale.strip():
            yield f"hypothesis index {idx} has empty rationale"


# ---------------------------------------------------------------------------
# Layer 2 — Q6 substring guard (reuses D.13)
# ---------------------------------------------------------------------------


def _check_q6_substrings(draft: CuriosityDraft) -> Iterable[str]:
    """Yield Q6 classifier-substring violations across the draft.

    Reuses ``synthesis.reviewer._scan_classifier_labels`` directly
    so D.12 + D.13 share the pattern set. Scans statement +
    rationale + rationale_ref of each hypothesis.

    NEVER yields the matched substring — only the label name (Q6
    meta-invariant; matches D.13's reviewer posture).
    """
    for idx, hyp in enumerate(draft.hypotheses):
        for label in _scan_classifier_labels(hyp.statement):
            yield (
                f"hypothesis index {idx} statement contains classifier-shaped substring ({label})"
            )
        for label in _scan_classifier_labels(hyp.rationale):
            yield (
                f"hypothesis index {idx} rationale contains classifier-shaped substring ({label})"
            )
        for label in _scan_classifier_labels(hyp.probe_directive.rationale_ref):
            yield (
                f"hypothesis index {idx} probe_directive.rationale_ref "
                f"contains classifier-shaped substring ({label})"
            )


# Re-export the Hypothesis import to discourage circular import paths
# in future tests (curiosity.reviewer is a leaf consumer of schemas;
# it does NOT export them).
__all__ = [
    "RETRY_HINT_Q6",
    "RETRY_HINT_SHAPE",
    "review",
]


# Keep `Hypothesis` referenced so the import is not pruned by ruff
# in environments where the module is loaded fresh; it documents the
# pydantic shape the reviewer consumes.
_ = Hypothesis
