"""synthesis v0.2 Task 17 — LLM hallucination guard tests (WI-Y13)."""

from __future__ import annotations

import pytest
from synthesis.validation.hallucination_guard import (
    HallucinationGuardViolationError,
    assert_findings_cited,
    extract_cited_finding_ids,
)


def test_extract_finding_ids() -> None:
    n = "The `CSPM-AWS-S3-001` and `MCSPM-AZURE-002` findings are critical."
    assert extract_cited_finding_ids(n) == {"CSPM-AWS-S3-001", "MCSPM-AZURE-002"}


def test_non_finding_backticks_ignored() -> None:
    # backticked prose / code spans are not finding ids.
    n = "See `findings.json`; the `class_uid` is 2004 and `narrative.md` was written."
    assert extract_cited_finding_ids(n) == set()


def test_clean_narrative_passes() -> None:
    n = "Posture: `CSPM-AWS-S3-001` is public."
    assert_findings_cited(n, {"CSPM-AWS-S3-001", "CSPM-AWS-S3-002"})  # does not raise


def test_hallucinated_id_raises() -> None:
    n = "The fleet has a critical `CSPM-AWS-S3-099` exposure."
    with pytest.raises(HallucinationGuardViolationError, match="CSPM-AWS-S3-099"):
        assert_findings_cited(n, {"CSPM-AWS-S3-001", "CSPM-AWS-S3-002"})


def test_one_of_many_hallucinated_raises() -> None:
    n = "Both `CSPM-AWS-S3-001` and `CSPM-AWS-S3-099` were found."
    with pytest.raises(HallucinationGuardViolationError):
        assert_findings_cited(n, {"CSPM-AWS-S3-001"})


def test_empty_narrative_passes() -> None:
    assert_findings_cited("", {"CSPM-AWS-S3-001"})


def test_no_finding_ids_passes() -> None:
    assert_findings_cited("No sensitive data was detected this scan window.", set())


def test_empty_source_with_citation_raises() -> None:
    with pytest.raises(HallucinationGuardViolationError):
        assert_findings_cited("Finding `D-1` is here.", set())


def test_multiple_hallucinated_listed_sorted() -> None:
    n = "`B-2` and `A-1` are fabricated."
    with pytest.raises(HallucinationGuardViolationError, match=r"\['A-1', 'B-2'\]"):
        assert_findings_cited(n, set())


def test_lowercase_token_ignored() -> None:
    # not finding-id-shaped (lowercase) -> not checked.
    assert extract_cited_finding_ids("`some-tool-name`") == set()


def test_all_cited_in_source_passes() -> None:
    n = "`A-1`, `B-2`, `C-3` all reviewed."
    assert_findings_cited(n, {"A-1", "B-2", "C-3"})
