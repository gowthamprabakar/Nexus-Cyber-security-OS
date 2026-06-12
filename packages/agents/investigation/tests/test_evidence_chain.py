"""investigation v0.2 Task 18 — assert_evidence_chain tests (WI-I12/H2)."""

from __future__ import annotations

import pytest
from investigation.schemas import Hypothesis
from investigation.validation.evidence_chain import (
    EVIDENCE_KINDS,
    EvidenceChainViolationError,
    assert_evidence_chain,
    malformed_refs,
)


def _hyp(refs: tuple[str, ...]) -> Hypothesis:
    return Hypothesis(hypothesis_id="h1", statement="s", confidence=0.5, evidence_refs=refs)


def test_kinds_frozen() -> None:
    assert frozenset({"audit_event", "finding", "entity"}) == EVIDENCE_KINDS


def test_intact_chain_ok() -> None:
    ev = {"finding:f1", "audit_event:a1", "entity:e1"}
    assert_evidence_chain(_hyp(("finding:f1", "entity:e1")), ev)


def test_all_three_kinds_ok() -> None:
    ev = {"finding:f1", "audit_event:a1", "entity:e1"}
    assert_evidence_chain(_hyp(("finding:f1", "audit_event:a1", "entity:e1")), ev)


def test_dangling_ref_raises() -> None:
    with pytest.raises(EvidenceChainViolationError, match="absent"):
        assert_evidence_chain(_hyp(("finding:f9",)), {"finding:f1"})


def test_malformed_missing_colon_raises() -> None:
    with pytest.raises(EvidenceChainViolationError, match="malformed"):
        assert_evidence_chain(_hyp(("findingf1",)), {"findingf1"})


def test_malformed_bad_kind_raises() -> None:
    with pytest.raises(EvidenceChainViolationError, match="malformed"):
        assert_evidence_chain(_hyp(("secret:f1",)), {"secret:f1"})


def test_malformed_empty_id_raises() -> None:
    with pytest.raises(EvidenceChainViolationError, match="malformed"):
        assert_evidence_chain(_hyp(("finding:",)), {"finding:"})


def test_malformed_surfaces_before_dangling() -> None:
    # one malformed + one dangling -> malformed message wins.
    with pytest.raises(EvidenceChainViolationError, match="malformed"):
        assert_evidence_chain(_hyp(("bad", "finding:f9")), {"finding:f1"})


def test_malformed_refs_lists_bad_only() -> None:
    h = _hyp(("finding:f1", "nope", "entity:e1"))
    assert malformed_refs(h) == ("nope",)


def test_message_cites_hypothesis_id() -> None:
    with pytest.raises(EvidenceChainViolationError, match="'h1'"):
        assert_evidence_chain(_hyp(("finding:f9",)), set())
