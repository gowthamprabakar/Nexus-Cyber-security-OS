"""synthesis v0.2 Task 3 — narrative-to-OCSF translator tests (Q1/WI-Y12)."""

from __future__ import annotations

from datetime import UTC, datetime

from synthesis.ocsf.narrative_translator import (
    derive_severity,
    render_narrative_markdown,
    translate_report_to_ocsf,
)
from synthesis.schemas import (
    ExecutiveSummary,
    NarrativeSection,
    SynthesisReport,
)

_T0 = datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)
_T1 = datetime(2026, 6, 1, 0, 5, 0, tzinfo=UTC)


def _report(*, sections=None, metrics=None, cited=None) -> SynthesisReport:
    return SynthesisReport(
        customer_id="c1",
        run_id="run-7",
        scan_started_at=_T0,
        scan_completed_at=_T1,
        executive_summary=ExecutiveSummary(
            paragraph="One public bucket.", key_metrics=metrics or {}
        ),
        sections=sections
        if sections is not None
        else [
            NarrativeSection(
                heading="Posture",
                body="`CSPM-AWS-S3-001` is public.",
                cited_finding_ids=["CSPM-AWS-S3-001"],
            )
        ],
        cited_finding_ids=cited if cited is not None else ["CSPM-AWS-S3-001"],
    )


def test_render_markdown() -> None:
    md = render_narrative_markdown(_report())
    assert md.startswith("## Posture") and "CSPM-AWS-S3-001" in md


def test_derive_severity_from_metrics() -> None:
    assert derive_severity(_report(metrics={"highest_severity": "critical"})) == "critical"


def test_derive_severity_default_medium() -> None:
    assert derive_severity(_report(metrics={})) == "medium"


def test_translate_to_ocsf_2004() -> None:
    f = translate_report_to_ocsf(_report())
    assert f["class_uid"] == 2004
    assert f["finding_info"]["uid"] == "SYN-run-7"
    assert f["finding_info"]["title"] == "Posture"


def test_narrative_and_source_in_unmapped() -> None:
    f = translate_report_to_ocsf(_report())
    assert "CSPM-AWS-S3-001" in f["unmapped"]["narrative_markdown"]
    assert f["unmapped"]["source_finding_ids"] == ["CSPM-AWS-S3-001"]
    assert f["unmapped"]["executive_summary"] == "One public bucket."


def test_detected_at_ms_from_completed() -> None:
    f = translate_report_to_ocsf(_report())
    assert f["time"] == int(_T1.timestamp() * 1000)


def test_explicit_finding_id_and_title() -> None:
    f = translate_report_to_ocsf(_report(), finding_id="SYN-X", title="Custom")
    assert f["finding_info"]["uid"] == "SYN-X" and f["finding_info"]["title"] == "Custom"


def test_empty_sections_default_title() -> None:
    f = translate_report_to_ocsf(_report(sections=[], cited=[]))
    assert f["finding_info"]["title"] == "Synthesis narrative"


def test_deterministic() -> None:
    assert translate_report_to_ocsf(_report()) == translate_report_to_ocsf(_report())
