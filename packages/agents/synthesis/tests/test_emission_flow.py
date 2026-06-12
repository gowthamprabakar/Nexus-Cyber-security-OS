"""synthesis v0.2 Task 4 — OCSF emission flow integration tests (Q1/WI-Y5)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from synthesis.ocsf.emission import (
    SYNTHESIS_FINDING_OUTPUT,
    build_synthesis_finding_json,
)
from synthesis.schemas import ExecutiveSummary, NarrativeSection, SynthesisReport


def _report() -> SynthesisReport:
    return SynthesisReport(
        customer_id="c1",
        run_id="run-7",
        scan_started_at=datetime(2026, 6, 1, tzinfo=UTC),
        scan_completed_at=datetime(2026, 6, 1, 0, 5, tzinfo=UTC),
        executive_summary=ExecutiveSummary(
            paragraph="One public bucket.", key_metrics={"highest_severity": "high"}
        ),
        sections=[
            NarrativeSection(
                heading="Posture",
                body="`CSPM-AWS-S3-001` is public.",
                cited_finding_ids=["CSPM-AWS-S3-001"],
            )
        ],
        cited_finding_ids=["CSPM-AWS-S3-001"],
    )


def test_output_filename() -> None:
    assert SYNTHESIS_FINDING_OUTPUT == "synthesis_finding.json"


def test_emission_is_valid_ocsf_2004_json() -> None:
    payload = json.loads(build_synthesis_finding_json(_report()))
    assert payload["class_uid"] == 2004
    assert payload["severity_id"] == 4  # high
    assert "CSPM-AWS-S3-001" in payload["unmapped"]["narrative_markdown"]


def test_emission_deterministic() -> None:
    assert build_synthesis_finding_json(_report()) == build_synthesis_finding_json(_report())


def test_emission_is_bytes() -> None:
    assert isinstance(build_synthesis_finding_json(_report()), bytes)
