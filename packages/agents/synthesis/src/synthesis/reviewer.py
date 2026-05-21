"""Stage 4 REVIEW — deterministic narrative validator.

The reviewer is the **second-line scrub** against classifier-substring
leakage (the first line is Stage 2 ENRICH's structured-fields-only
context bundle). When the LLM hallucinates a "looks plausible"
SSN / credit-card / AWS-access-key / JWT inside the rendered
narrative, the reviewer rejects the draft and the driver re-runs the
narration call with the ``q6_violation_retry_hint=True`` flag set.

**Two layers:**

1. **Shape checks** — every section has a non-empty heading + non-
   empty body; the executive summary paragraph is non-empty; at
   least one section is present.
2. **Q6 substring guard** — regex pass over the rendered narrative
   body + executive_summary paragraph for known classifier patterns
   (SSN, credit-card with Luhn, AWS access key, JWT). Reuses the
   patterns shipped by D.5 (Data Security Agent) for posture
   consistency — both agents enforce the same Q6 contract.

Pure-function over ``SynthesisDraft``. No LLM, no I/O, no module-
level state. Eval case 007 (``no_classifier_substrings``) is the
regression probe; WI-2 is the acceptance gate at close.

The retry-hint contract:

- ``retry_hint == "q6_violation"`` -> driver re-enters narrate()
  with ``q6_violation_retry_hint=True``.
- ``retry_hint == "shape_violation"`` -> driver gives up (the LLM
  produced structurally broken output; retrying probably won't
  help; driver emits the fallback "synthesis failed" narrative).
- ``retry_hint == ""`` -> verdict passed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Final

from synthesis.narrator import SynthesisDraft
from synthesis.schemas import ReviewVerdict

# Q6 classifier patterns. Lifted verbatim from D.5's
# ``data_security.classifiers.patterns`` so the two agents enforce
# the same Q6 contract end-to-end. D.5's classifier returns the
# label only (never the matched substring); D.13's reviewer scans
# the LLM-rendered narrative for the same patterns and rejects on
# match.

_AWS_ACCESS_KEY_RE: Final[re.Pattern[str]] = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_JWT_RE: Final[re.Pattern[str]] = re.compile(
    r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b"
)
_SSN_RE: Final[re.Pattern[str]] = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# Credit-card: 13-19 digits with optional separators. Luhn-valid
# matches are real cards; Luhn-invalid look-alikes (random 16-digit
# IDs, account references, ULID fragments) pass through.
_CREDIT_CARD_RE: Final[re.Pattern[str]] = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")

# Retry-hint string constants. Stable contract — the driver branches
# on these values to decide retry-vs-fallback.
RETRY_HINT_Q6: Final[str] = "q6_violation"
RETRY_HINT_SHAPE: Final[str] = "shape_violation"


def review(draft: SynthesisDraft) -> ReviewVerdict:
    """Return the deterministic verdict for ``draft``.

    Pass -> ``ReviewVerdict(passed=True)``. Fail -> ``passed=False``
    + a ``retry_hint`` string the driver can branch on + a list of
    human-readable ``violations`` strings.

    Q6 violations take precedence: if both shape AND Q6 fail, the
    verdict's ``retry_hint`` is ``q6_violation`` (Q6 retry is
    cheaper than giving up).
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


def _check_shape(draft: SynthesisDraft) -> Iterable[str]:
    """Yield shape-level violation strings for ``draft``.

    Placeholder bodies (``[section narration unavailable]``, written
    by the narrator on per-section failure) PASS the shape check —
    they are degraded but legal output. Empty / whitespace-only
    bodies fail.
    """
    if not draft.sections:
        yield "narrative has zero sections"

    for idx, section in enumerate(draft.sections):
        if not section.heading.strip():
            yield f"section {idx} has empty heading"
        if not section.body.strip():
            yield f"section {section.heading!r} has empty body"

    if not draft.executive_summary.paragraph.strip():
        yield "executive_summary paragraph is empty"


# ---------------------------------------------------------------------------
# Layer 2 — Q6 classifier-substring guard
# ---------------------------------------------------------------------------


def _check_q6_substrings(draft: SynthesisDraft) -> Iterable[str]:
    """Yield Q6 classifier-substring violations across the draft.

    Scans every per-section body + the executive-summary paragraph.
    For each classifier-pattern match, yields one violation string
    naming the classifier label and the section heading where the
    match was found (NEVER the matched substring itself — Q6
    invariant applies to the reviewer's own audit log too).
    """
    for section in draft.sections:
        for label in _scan_classifier_labels(section.body):
            yield (
                f"section {section.heading!r} body contains classifier-shaped substring ({label})"
            )

    for label in _scan_classifier_labels(draft.executive_summary.paragraph):
        yield (f"executive_summary paragraph contains classifier-shaped substring ({label})")


def _scan_classifier_labels(text: str) -> Iterable[str]:
    """Yield classifier labels found in ``text``.

    Unlike D.5's ``classify`` (which returns the first match's label
    only), this scans for ALL classifier patterns so the reviewer's
    violation list captures every leak in a single review pass. The
    driver may then surface all of them in the audit log.

    NEVER yields the matched substring — only the label name.
    """
    if _AWS_ACCESS_KEY_RE.search(text):
        yield "aws_access_key"
    if _JWT_RE.search(text):
        yield "jwt"
    if _SSN_RE.search(text):
        yield "ssn"
    cc_match = _CREDIT_CARD_RE.search(text)
    if cc_match:
        digits = re.sub(r"[^0-9]", "", cc_match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            yield "credit_card"


def _luhn_valid(digits: str) -> bool:
    """Standard Luhn check-digit validation.

    Filters credit-card-shaped numbers that aren't valid cards
    (random 16-digit IDs, ULIDs reshaped, account references).
    """
    total = 0
    for i, digit in enumerate(reversed(digits)):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


__all__ = [
    "RETRY_HINT_Q6",
    "RETRY_HINT_SHAPE",
    "review",
]
