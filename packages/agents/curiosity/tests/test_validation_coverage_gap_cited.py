"""curiosity v0.2 Task 14 — assert_coverage_gap_cited tests (WI-X11)."""

from __future__ import annotations

import pytest
from curiosity.schemas import CoverageGap, Hypothesis, ProbeDirective
from curiosity.validation.coverage_gap_cited import (
    CoverageGapCitationViolationError,
    assert_coverage_gap_cited,
    detected_gap_ids,
)


def _gap(region: str) -> CoverageGap:
    return CoverageGap(
        region=region, asset_count=15, days_since_last_finding=40, severity_hint="medium"
    )


def _hyp(region: str) -> Hypothesis:
    return Hypothesis(
        statement="region may be under-scanned.",
        rationale="assets present, no recent findings; worth a scan.",
        probe_directive=ProbeDirective(
            target_agent="investigation", target_finding_id="F-1", action="investigate"
        ),
        cited_gap=_gap(region),
    )


def test_detected_gap_ids_namespace() -> None:
    assert detected_gap_ids([_gap("eu-west-1"), _gap("us-east-1")]) == {
        "region:eu-west-1",
        "region:us-east-1",
    }


def test_cited_detected_gap_ok() -> None:
    detected = detected_gap_ids([_gap("eu-west-1")])
    assert_coverage_gap_cited(_hyp("eu-west-1"), detected)


def test_uncited_gap_raises() -> None:
    detected = detected_gap_ids([_gap("eu-west-1")])
    with pytest.raises(CoverageGapCitationViolationError, match="region:ap-south-1"):
        assert_coverage_gap_cited(_hyp("ap-south-1"), detected)


def test_empty_detected_raises() -> None:
    with pytest.raises(CoverageGapCitationViolationError):
        assert_coverage_gap_cited(_hyp("eu-west-1"), set())
