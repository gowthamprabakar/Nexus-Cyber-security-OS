"""curiosity v0.2 Task 4 — OCSF emission flow tests (Q1/WI-X5)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from curiosity.ocsf.emission import (
    emit_curiosity_findings,
    render_curiosity_findings_json,
)
from curiosity.schemas import (
    CoverageGap,
    CuriosityClaim,
    CuriosityReport,
    Hypothesis,
    ProbeDirective,
)


def _claim(claim_id: str) -> CuriosityClaim:
    hyp = Hypothesis(
        statement="region may be under-scanned.",
        rationale="assets present, no recent findings; worth a scan.",
        probe_directive=ProbeDirective(
            target_agent="investigation", target_finding_id="F-1", action="investigate"
        ),
        cited_gap=CoverageGap(
            region="us-east-1", asset_count=11, days_since_last_finding=35, severity_hint="high"
        ),
    )
    return CuriosityClaim(
        claim_id=claim_id,
        customer_id="c1",
        hypothesis=hyp,
        emitted_at=datetime(2026, 6, 13, tzinfo=UTC),
    )


def _report(*claim_ids: str) -> CuriosityReport:
    return CuriosityReport(
        customer_id="c1",
        run_id="r1",
        scan_started_at=datetime(2026, 6, 13, tzinfo=UTC),
        scan_completed_at=datetime(2026, 6, 13, tzinfo=UTC),
        claims=[_claim(cid) for cid in claim_ids],
    )


def test_one_finding_per_claim() -> None:
    findings = emit_curiosity_findings(
        _report("01HV0T0000000000000000AB12", "01HV0T0000000000000000AB13")
    )
    assert len(findings) == 2
    assert all(f["class_uid"] == 2004 for f in findings)


def test_empty_report_empty_findings() -> None:
    assert emit_curiosity_findings(_report()) == []


def test_render_json_is_parseable_and_sorted() -> None:
    out = render_curiosity_findings_json(_report("01HV0T0000000000000000AB12"))
    parsed = json.loads(out)
    assert parsed[0]["finding_info"]["uid"] == "01HV0T0000000000000000AB12"
    # deterministic render.
    assert out == render_curiosity_findings_json(_report("01HV0T0000000000000000AB12"))
