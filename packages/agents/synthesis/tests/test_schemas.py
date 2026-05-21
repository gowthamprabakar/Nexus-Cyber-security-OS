"""Tests — ``synthesis.schemas`` (Task 2).

Verifies the internal pydantic types that flow through the
synthesis pipeline: ContextBundle, OutlineSection, SynthesisOutline,
NarrativeSection, ExecutiveSummary, SynthesisReport, ReviewVerdict.

No OCSF re-export in v0.1 per Q1.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from synthesis.schemas import (
    ContextBundle,
    ExecutiveSummary,
    NarrativeSection,
    OutlineSection,
    ReviewVerdict,
    SynthesisOutline,
    SynthesisReport,
)


def _exec_summary() -> ExecutiveSummary:
    return ExecutiveSummary(
        paragraph="The 2026-05-21 scan window surfaced 12 control failures across F.3, D.5, and D.7 sources.",
        key_metrics={"total_findings": 12, "critical": 1, "high": 6},
    )


def _section(heading: str = "Identity posture") -> NarrativeSection:
    return NarrativeSection(
        heading=heading,
        body="Two IAM users were missing MFA. CIS 1.10 fails for both.",
        cited_finding_ids=["VULN-x-CVE-2024-1", "COMPLIANCE-CIS_AWS_V3-1_10-001-aggregated"],
    )


# ---------------------------------------------------------------------------
# ContextBundle
# ---------------------------------------------------------------------------


def test_context_bundle_defaults() -> None:
    cb = ContextBundle(
        customer_id="acme",
        scan_window_start=datetime(2026, 5, 21, tzinfo=UTC),
        scan_window_end=datetime(2026, 5, 21, 1, tzinfo=UTC),
    )
    assert cb.investigation_conclusions == []
    assert cb.compliance_failures == []
    assert cb.cloud_posture_findings == []
    assert cb.severity_counts == {}
    assert cb.total_findings == 0


def test_context_bundle_is_frozen() -> None:
    cb = ContextBundle(
        customer_id="acme",
        scan_window_start=datetime(2026, 5, 21, tzinfo=UTC),
        scan_window_end=datetime(2026, 5, 21, 1, tzinfo=UTC),
    )
    with pytest.raises(ValidationError):
        cb.customer_id = "evil"  # type: ignore[misc]


def test_context_bundle_carries_severity_counts() -> None:
    cb = ContextBundle(
        customer_id="acme",
        scan_window_start=datetime(2026, 5, 21, tzinfo=UTC),
        scan_window_end=datetime(2026, 5, 21, 1, tzinfo=UTC),
        severity_counts={"critical": 1, "high": 4, "medium": 7, "low": 0, "info": 0},
        total_findings=12,
    )
    assert cb.severity_counts["high"] == 4
    assert cb.total_findings == 12


# ---------------------------------------------------------------------------
# OutlineSection + SynthesisOutline
# ---------------------------------------------------------------------------


def test_outline_section_minimum_shape() -> None:
    s = OutlineSection(heading="x", intent="y")
    assert s.cited_finding_ids == []


def test_outline_section_caps_cited_ids_at_max() -> None:
    too_many = [f"VULN-{i}" for i in range(17)]
    with pytest.raises(ValidationError):
        OutlineSection(heading="x", intent="y", cited_finding_ids=too_many)


def test_outline_section_rejects_empty_cited_id() -> None:
    with pytest.raises(ValidationError):
        OutlineSection(heading="x", intent="y", cited_finding_ids=["VULN-1", "  "])


def test_synthesis_outline_min_one_section() -> None:
    with pytest.raises(ValidationError):
        SynthesisOutline(sections=[], overall_narrative_intent="x")


def test_synthesis_outline_caps_sections() -> None:
    sections = [OutlineSection(heading=f"h{i}", intent="x") for i in range(13)]
    with pytest.raises(ValidationError):
        SynthesisOutline(sections=sections, overall_narrative_intent="x")


def test_synthesis_outline_full_shape_round_trip() -> None:
    outline = SynthesisOutline(
        overall_narrative_intent="Risk summary for 2026-05-21",
        sections=[
            OutlineSection(
                heading="Identity posture",
                intent="Two IAM users without MFA",
                cited_finding_ids=["VULN-1", "COMPLIANCE-1"],
            ),
            OutlineSection(
                heading="Storage exposure",
                intent="One public S3 bucket carrying sensitive data",
            ),
        ],
    )
    assert len(outline.sections) == 2
    assert outline.sections[0].cited_finding_ids == ["VULN-1", "COMPLIANCE-1"]


# ---------------------------------------------------------------------------
# NarrativeSection + ExecutiveSummary
# ---------------------------------------------------------------------------


def test_narrative_section_requires_non_empty_body() -> None:
    with pytest.raises(ValidationError):
        NarrativeSection(heading="x", body="")


def test_narrative_section_caps_cited_ids() -> None:
    too_many = [f"VULN-{i}" for i in range(17)]
    with pytest.raises(ValidationError):
        NarrativeSection(heading="x", body="y", cited_finding_ids=too_many)


def test_executive_summary_caps_paragraph_length() -> None:
    long = "x" * 2001
    with pytest.raises(ValidationError):
        ExecutiveSummary(paragraph=long)


def test_executive_summary_key_metrics_accepts_int_and_str() -> None:
    es = ExecutiveSummary(
        paragraph="x", key_metrics={"total_findings": 12, "top_control": "CIS 2.1.4"}
    )
    assert es.key_metrics["total_findings"] == 12
    assert es.key_metrics["top_control"] == "CIS 2.1.4"


# ---------------------------------------------------------------------------
# SynthesisReport
# ---------------------------------------------------------------------------


def test_synthesis_report_minimum_shape() -> None:
    report = SynthesisReport(
        customer_id="acme",
        run_id="run_1",
        scan_started_at=datetime(2026, 5, 21, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 21, 1, tzinfo=UTC),
        executive_summary=_exec_summary(),
    )
    assert report.total_sections == 0
    assert report.total_cited_findings == 0
    assert report.review_retries == 0


def test_synthesis_report_total_sections_counts_list() -> None:
    report = SynthesisReport(
        customer_id="acme",
        run_id="run_1",
        scan_started_at=datetime(2026, 5, 21, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 21, 1, tzinfo=UTC),
        executive_summary=_exec_summary(),
        sections=[_section("a"), _section("b")],
    )
    assert report.total_sections == 2


def test_synthesis_report_carries_review_retries() -> None:
    report = SynthesisReport(
        customer_id="acme",
        run_id="run_1",
        scan_started_at=datetime(2026, 5, 21, tzinfo=UTC),
        scan_completed_at=datetime(2026, 5, 21, 1, tzinfo=UTC),
        executive_summary=_exec_summary(),
        review_retries=2,
    )
    assert report.review_retries == 2


def test_synthesis_report_review_retries_must_be_non_negative() -> None:
    with pytest.raises(ValidationError):
        SynthesisReport(
            customer_id="acme",
            run_id="run_1",
            scan_started_at=datetime(2026, 5, 21, tzinfo=UTC),
            scan_completed_at=datetime(2026, 5, 21, 1, tzinfo=UTC),
            executive_summary=_exec_summary(),
            review_retries=-1,
        )


# ---------------------------------------------------------------------------
# ReviewVerdict
# ---------------------------------------------------------------------------


def test_review_verdict_pass_default_no_violations() -> None:
    v = ReviewVerdict(passed=True)
    assert v.passed is True
    assert v.violations == []
    assert v.retry_hint == ""


def test_review_verdict_q6_violation_carries_hint() -> None:
    v = ReviewVerdict(
        passed=False,
        retry_hint="q6_violation",
        violations=["narrative contains SSN-shaped substring"],
    )
    assert v.passed is False
    assert v.retry_hint == "q6_violation"
    assert "SSN" in v.violations[0]


def test_review_verdict_is_frozen() -> None:
    v = ReviewVerdict(passed=True)
    with pytest.raises(ValidationError):
        v.passed = False  # type: ignore[misc]
