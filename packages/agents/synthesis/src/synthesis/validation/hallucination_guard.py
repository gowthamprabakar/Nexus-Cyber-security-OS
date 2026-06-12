"""LLM hallucination guard — code-level (synthesis v0.2 Task 17, WI-Y13).

The third of this cycle's LLM-agent invariants, and a **new institutional pattern**: the first
code-level guard against an LLM **hallucinating structured references**. Per **H2** the narrative
cites findings by id inline (backtick-wrapped); every cited finding id **must** exist in the
source set the narrator was given. ``assert_findings_cited`` extracts the backticked finding ids
from the rendered narrative and raises if any is **not** in the source set — catching, e.g., a
narrative that cites ``CSPM-AWS-S3-099`` when only ``-001`` / ``-002`` were in scope.

This is the template D.7 Investigation, D.12 Curiosity, and A.4 Meta-Harness inherit, so the
pattern is kept deliberately simple + conservative: only tokens that *look like* finding ids
(uppercase-led, hyphen-segmented) are checked — backticked prose like ``findings.json`` or
``class_uid`` is ignored, so the guard never raises on non-finding code spans.
"""

from __future__ import annotations

import re

#: Backtick-wrapped span.
_BACKTICK_RE = re.compile(r"`([^`]+)`")
#: A finding-id shape: an uppercase-led segment then one-or-more ``-SEGMENT`` (caps/digits).
_FINDING_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")


class HallucinationGuardViolationError(RuntimeError):
    """Raised when a narrative cites a finding id absent from the source set (WI-Y13)."""


def extract_cited_finding_ids(narrative: str) -> set[str]:
    """The finding ids the narrative cites (backtick-wrapped, finding-id-shaped)."""
    out: set[str] = set()
    for match in _BACKTICK_RE.finditer(narrative):
        token = match.group(1).strip()
        if _FINDING_ID_RE.match(token):
            out.add(token)
    return out


def assert_findings_cited(narrative: str, source_findings: set[str]) -> None:
    """Hard guard — every finding id cited in ``narrative`` must be in ``source_findings``.

    Per H2 (cite findings by id inline) this catches LLM hallucination of finding ids.
    """
    cited = extract_cited_finding_ids(narrative)
    hallucinated = cited - set(source_findings)
    if hallucinated:
        raise HallucinationGuardViolationError(
            f"Narrative cites finding ids not in the source set: {sorted(hallucinated)}. "
            f"LLM hallucination detected — per H2, cite by id inline only."
        )
