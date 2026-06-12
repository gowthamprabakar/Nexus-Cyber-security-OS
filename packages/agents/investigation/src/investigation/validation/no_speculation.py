"""No-speculation invariant — code-level (investigation v0.2 Task 19, WI-I13/H1).

The third (and closing) of D.7's **three NEW** invariants. Per **H1** ("evidence first") a
hypothesis with **zero** evidence_refs is pure speculation — the schema enforces ``min_length=1``
at construction, and this guard enforces the same contract at the LLM/synthesis boundary, where a
model could otherwise emit a confident-sounding but ungrounded claim. ``assert_no_speculation``
raises on an empty chain (never worked around). Distinct from Task-18 ``assert_evidence_chain``
(which validates that present links are well-formed and resolve): this is the floor — *at least
one* citation must exist. Pure + deterministic.
"""

from __future__ import annotations

from investigation.schemas import Hypothesis


class SpeculationViolationError(RuntimeError):
    """Raised when a hypothesis carries no evidence at all — pure speculation (WI-I13)."""


def assert_no_speculation(hypothesis: Hypothesis) -> None:
    """Hard guard — raise if ``hypothesis`` has zero evidence_refs (H1/WI-I13).

    The evidence floor: a hypothesis must cite at least one evidence item. Grounding *quality*
    (well-formed, resolving links) is Task-18 ``assert_evidence_chain``; this is the floor.
    """
    if not hypothesis.evidence_refs:
        raise SpeculationViolationError(
            f"Hypothesis {hypothesis.hypothesis_id!r} cites no evidence; a hypothesis must rest "
            f"on at least one evidence item, never pure speculation (H1/WI-I13)."
        )
