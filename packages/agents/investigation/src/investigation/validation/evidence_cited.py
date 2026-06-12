"""Evidence-citation guard — code-level (investigation v0.2 Task 16, WI-I10).

**Inherited + extended from D.13's hallucination guard.** D.13's version checks a narrative
cites only finding ids in the source set; D.7 extends it to a **hypothesis's evidence_refs**
(``<kind>:<id>`` — audit_event / finding / entity), which MUST all resolve against the collected
evidence set. Where the Task-11 filter *drops* an ungrounded hypothesis, this guard **raises** —
a hypothesis that survived to a code path expecting resolved refs must not carry phantom ones.
"""

from __future__ import annotations

from investigation.schemas import Hypothesis


class EvidenceCitationViolationError(RuntimeError):
    """Raised when a hypothesis cites evidence refs absent from the collected set (WI-I10)."""


def assert_findings_cited(hypothesis: Hypothesis, evidence_set: set[str]) -> None:
    """Hard guard — every evidence_ref of ``hypothesis`` must resolve against ``evidence_set``.

    Extends the D.13 hallucination guard to forensic evidence refs (per H2 — evidence is sacred).
    """
    unresolved = set(hypothesis.evidence_refs) - evidence_set
    if unresolved:
        raise EvidenceCitationViolationError(
            f"Hypothesis {hypothesis.hypothesis_id!r} cites unresolved evidence: "
            f"{sorted(unresolved)}. Per H2 — every evidence_ref must resolve (WI-I10)."
        )
