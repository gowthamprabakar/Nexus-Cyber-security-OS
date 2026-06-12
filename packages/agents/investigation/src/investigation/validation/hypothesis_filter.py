"""Evidence-refs validator (investigation v0.2 Task 11, H3/WI-I12).

The VALIDATE-stage filter: a hypothesis is **grounded** iff it carries >= 1 evidence_ref and
**every** ref resolves against the collected evidence set (``<kind>:<id>`` — audit_event /
finding / entity). Per **H3** an ungrounded hypothesis is **dropped** (the v0.1 behavior,
preserved here). The hard, raise-on-violation guards land in M7/M8 (assert_findings_cited /
assert_evidence_chain / assert_no_speculation) — this module is the non-fatal filter they build
on. Pure + deterministic.
"""

from __future__ import annotations

from collections.abc import Sequence

from investigation.schemas import Hypothesis


def unresolved_refs(hypothesis: Hypothesis, evidence_set: set[str]) -> set[str]:
    """The hypothesis's evidence_refs that do NOT resolve against the evidence set."""
    return set(hypothesis.evidence_refs) - evidence_set


def is_grounded(hypothesis: Hypothesis, evidence_set: set[str]) -> bool:
    """True iff the hypothesis has >= 1 evidence_ref and all of them resolve (H1 + H2)."""
    refs = set(hypothesis.evidence_refs)
    return bool(refs) and refs <= evidence_set


def filter_valid_hypotheses(
    hypotheses: Sequence[Hypothesis], evidence_set: set[str]
) -> tuple[Hypothesis, ...]:
    """Drop any hypothesis that cites unresolved evidence or has none (H3 drop behavior)."""
    return tuple(h for h in hypotheses if is_grounded(h, evidence_set))
