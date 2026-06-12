"""Skip-LLM-when-no-gaps invariant — code-level (curiosity v0.2 Task 17, WI-X15/H4 — NEW).

The third (and closing) of D.12's **three NEW** invariants. Per **H4** most scan windows DETECT no
coverage gaps; in those windows the HYPOTHESIZE stage is **skipped** — calling the LLM with an
empty gap list is wasted cost AND invites a hallucination (a model asked to hypothesize with no
grounding will invent one). ``assert_llm_only_with_gaps`` is the hard guard called BEFORE every
LLM invocation: an LLM call with zero gaps raises.

NOTE: this module lives under ``curiosity/gate/`` — deliberately NOT ``curiosity/llm/`` — so the
``test_no_per_agent_llm_module`` deviation guard (WI-X12) stays green. It is a gate, not an LLM
client.
"""

from __future__ import annotations

from collections.abc import Sized


class UnnecessaryLLMCallError(RuntimeError):
    """Raised when the LLM is invoked despite zero detected gaps (WI-X15/H4)."""


def assert_llm_only_with_gaps(gaps: Sized, llm_called: bool) -> None:
    """Hard guard — raise if ``llm_called`` is True while ``gaps`` is empty (H4/WI-X15).

    The cheap, common path (no gaps -> no LLM) passes; an empty-gap LLM call raises before the
    spend + the hallucination risk.
    """
    if llm_called and len(gaps) == 0:
        raise UnnecessaryLLMCallError(
            "LLM invoked with an empty gaps list. Per H4: skip the LLM when no gaps are detected "
            "(cost discipline + hallucination prevention, WI-X15)."
        )
