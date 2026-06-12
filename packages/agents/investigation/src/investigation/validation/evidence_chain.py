"""Evidence-chain integrity invariant — code-level (investigation v0.2 Task 18, WI-I12/H2).

The second of D.7's **three NEW** invariants. Where Task-16 ``assert_findings_cited`` (inherited
from D.13) checks that citations *resolve*, ``assert_evidence_chain`` is the stronger
Orchestrator-Workers guard: every ``evidence_ref`` must be a **well-formed link** —
``<kind>:<id>`` with ``kind`` in {audit_event, finding, entity}, the evidence-ref namespace from
Task 4 — **and** resolve against the collected evidence set. A hypothesis is admissible only when
its entire chain is sound; a malformed or dangling link raises (never worked around). Per **H2**
every hypothesis links to concrete evidence via the chain. Pure + deterministic.
"""

from __future__ import annotations

from investigation.schemas import Hypothesis

#: The evidence-ref namespace (Task 4): an evidence_ref is ``<kind>:<id>``.
EVIDENCE_KINDS: frozenset[str] = frozenset({"audit_event", "finding", "entity"})


class EvidenceChainViolationError(RuntimeError):
    """Raised when a hypothesis's evidence chain is malformed or dangling (WI-I12)."""


def malformed_refs(hypothesis: Hypothesis) -> tuple[str, ...]:
    """The evidence_refs that are not a well-formed ``<kind>:<id>`` link."""
    bad: list[str] = []
    for ref in hypothesis.evidence_refs:
        kind, sep, ident = ref.partition(":")
        if not sep or kind not in EVIDENCE_KINDS or not ident:
            bad.append(ref)
    return tuple(bad)


def assert_evidence_chain(hypothesis: Hypothesis, evidence_set: set[str]) -> None:
    """Hard guard — raise if any evidence_ref is malformed or does not resolve (H2/WI-I12).

    Malformed links surface before dangling ones (a bad shape can't resolve meaningfully).
    """
    bad = malformed_refs(hypothesis)
    if bad:
        raise EvidenceChainViolationError(
            f"Hypothesis {hypothesis.hypothesis_id!r} has malformed evidence links {bad}; "
            f"each ref must be '<kind>:<id>' with kind in {sorted(EVIDENCE_KINDS)} (WI-I12)."
        )
    dangling = set(hypothesis.evidence_refs) - evidence_set
    if dangling:
        raise EvidenceChainViolationError(
            f"Hypothesis {hypothesis.hypothesis_id!r} cites evidence {sorted(dangling)} absent "
            f"from the collected set; the evidence chain must be intact (H2/WI-I12)."
        )
