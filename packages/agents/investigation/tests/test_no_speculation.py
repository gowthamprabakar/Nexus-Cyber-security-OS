"""investigation v0.2 Task 19 — assert_no_speculation tests (WI-I13/H1)."""

from __future__ import annotations

import pytest
from investigation.schemas import Hypothesis
from investigation.validation.no_speculation import (
    SpeculationViolationError,
    assert_no_speculation,
)


def _hyp(refs: tuple[str, ...]) -> Hypothesis:
    return Hypothesis(hypothesis_id="h1", statement="s", confidence=0.5, evidence_refs=refs)


def test_one_ref_ok() -> None:
    assert_no_speculation(_hyp(("finding:f1",)))


def test_many_refs_ok() -> None:
    assert_no_speculation(_hyp(("finding:f1", "audit_event:a1", "entity:e1")))


def test_empty_refs_raises() -> None:
    # the schema forbids min_length=0 at construction, so build then blank the field to
    # exercise the synthesis-boundary guard directly.
    h = _hyp(("finding:f1",))
    object.__setattr__(h, "evidence_refs", ())
    with pytest.raises(SpeculationViolationError, match="no evidence"):
        assert_no_speculation(h)


def test_message_mentions_speculation() -> None:
    h = _hyp(("finding:f1",))
    object.__setattr__(h, "evidence_refs", ())
    with pytest.raises(SpeculationViolationError, match="speculation"):
        assert_no_speculation(h)


def test_message_cites_hypothesis_id() -> None:
    h = _hyp(("finding:f1",))
    object.__setattr__(h, "evidence_refs", ())
    with pytest.raises(SpeculationViolationError, match="'h1'"):
        assert_no_speculation(h)


def test_schema_blocks_empty_at_construction() -> None:
    # defense in depth: the schema itself rejects an empty chain.
    with pytest.raises(ValueError, match=r"evidence_refs|at least|length"):
        _hyp(())
