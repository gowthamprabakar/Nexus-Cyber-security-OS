"""investigation v0.2 Task 16 — evidence-citation guard tests (WI-I10)."""

from __future__ import annotations

import pytest
from investigation.schemas import Hypothesis
from investigation.validation.evidence_cited import (
    EvidenceCitationViolationError,
    assert_findings_cited,
)


def _h(refs: tuple[str, ...]) -> Hypothesis:
    return Hypothesis(hypothesis_id="h1", statement="s", confidence=0.5, evidence_refs=refs)


_EVIDENCE = {"finding:F-1", "audit_event:A-1", "entity:E-1"}


def test_all_resolved_passes() -> None:
    assert_findings_cited(_h(("finding:F-1", "audit_event:A-1")), _EVIDENCE)  # no raise


def test_unresolved_raises() -> None:
    with pytest.raises(EvidenceCitationViolationError, match="finding:F-99"):
        assert_findings_cited(_h(("finding:F-99",)), _EVIDENCE)


def test_partial_unresolved_raises_lists_only_unresolved() -> None:
    with pytest.raises(EvidenceCitationViolationError, match=r"\['entity:E-9'\]"):
        assert_findings_cited(_h(("finding:F-1", "entity:E-9")), _EVIDENCE)


def test_all_three_kinds_resolve() -> None:
    assert_findings_cited(_h(("finding:F-1", "audit_event:A-1", "entity:E-1")), _EVIDENCE)


def test_empty_evidence_set_with_refs_raises() -> None:
    with pytest.raises(EvidenceCitationViolationError):
        assert_findings_cited(_h(("finding:F-1",)), set())


def test_message_cites_hypothesis_id() -> None:
    with pytest.raises(EvidenceCitationViolationError, match="h1"):
        assert_findings_cited(_h(("finding:F-99",)), _EVIDENCE)
