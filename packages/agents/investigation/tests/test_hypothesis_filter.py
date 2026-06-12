"""investigation v0.2 Task 11 — evidence-refs validator tests (H3/WI-I12)."""

from __future__ import annotations

from investigation.schemas import Hypothesis
from investigation.validation.hypothesis_filter import (
    filter_valid_hypotheses,
    is_grounded,
    unresolved_refs,
)


def _h(hid: str, refs: tuple[str, ...]) -> Hypothesis:
    return Hypothesis(hypothesis_id=hid, statement="s", confidence=0.5, evidence_refs=refs)


_EVIDENCE = {"finding:F-1", "audit_event:A-1", "entity:E-1"}


def test_grounded_all_resolve() -> None:
    assert is_grounded(_h("h1", ("finding:F-1", "audit_event:A-1")), _EVIDENCE) is True


def test_not_grounded_unresolved() -> None:
    assert is_grounded(_h("h2", ("finding:F-99",)), _EVIDENCE) is False


def test_unresolved_refs() -> None:
    assert unresolved_refs(_h("h3", ("finding:F-1", "finding:F-99")), _EVIDENCE) == {"finding:F-99"}


def test_filter_drops_ungrounded() -> None:
    hyps = [_h("ok", ("finding:F-1",)), _h("bad", ("finding:F-99",))]
    kept = filter_valid_hypotheses(hyps, _EVIDENCE)
    assert [h.hypothesis_id for h in kept] == ["ok"]


def test_filter_keeps_all_grounded() -> None:
    hyps = [_h("a", ("finding:F-1",)), _h("b", ("entity:E-1",))]
    assert len(filter_valid_hypotheses(hyps, _EVIDENCE)) == 2


def test_filter_empty() -> None:
    assert filter_valid_hypotheses([], _EVIDENCE) == ()


def test_partial_unresolved_drops_whole_hypothesis() -> None:
    # one bad ref among good ones still drops the hypothesis (H2 — all must resolve).
    hyps = [_h("mixed", ("finding:F-1", "finding:F-99"))]
    assert filter_valid_hypotheses(hyps, _EVIDENCE) == ()
