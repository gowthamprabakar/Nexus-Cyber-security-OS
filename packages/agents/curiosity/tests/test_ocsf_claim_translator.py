"""curiosity v0.2 Task 3 — claim-to-OCSF translator tests (Q1/WI-X6)."""

from __future__ import annotations

from datetime import UTC, datetime

from curiosity.ocsf.claim_translator import claim_to_ocsf, coverage_gap_id
from curiosity.schemas import (
    CoverageGap,
    CuriosityClaim,
    Hypothesis,
    ProbeDirective,
)

_CLAIM_ID = "01HV0T0000000000000000AB12"


def _gap() -> CoverageGap:
    return CoverageGap(
        region="eu-west-1", asset_count=12, days_since_last_finding=40, severity_hint="medium"
    )


def _claim() -> CuriosityClaim:
    hyp = Hypothesis(
        statement="eu-west-1 may be under-scanned.",
        rationale="12 assets, no findings in 40 days; worth a posture scan.",
        probe_directive=ProbeDirective(
            target_agent="investigation",
            target_resource_arn="arn:aws:ec2:eu-west-1:1:instance/i-1",
            action="scan",
        ),
        cited_gap=_gap(),
    )
    return CuriosityClaim(
        claim_id=_CLAIM_ID,
        customer_id="cust-1",
        hypothesis=hyp,
        emitted_at=datetime(2026, 6, 13, tzinfo=UTC),
    )


def test_coverage_gap_id_region_namespace() -> None:
    assert coverage_gap_id(_gap()) == "region:eu-west-1"


def test_translates_to_2004() -> None:
    out = claim_to_ocsf(_claim())
    assert out["class_uid"] == 2004
    assert out["finding_info"]["uid"] == _CLAIM_ID


def test_unmapped_carries_claim() -> None:
    unmapped = claim_to_ocsf(_claim())["unmapped"]
    assert unmapped["coverage_gap_id"] == "region:eu-west-1"
    assert unmapped["statement"] == "eu-west-1 may be under-scanned."
    assert unmapped["probe_directive"]["target_agent"] == "investigation"


def test_severity_from_gap_hint() -> None:
    assert claim_to_ocsf(_claim())["severity_id"] == 3  # medium


def test_source_claim_unchanged() -> None:
    # WI-X6: translation is additive — the CuriosityClaim is frozen + untouched.
    claim = _claim()
    before = claim.model_dump(mode="json")
    claim_to_ocsf(claim)
    assert claim.model_dump(mode="json") == before


def test_time_is_emitted_at_ms() -> None:
    out = claim_to_ocsf(_claim())
    assert out["time"] == int(datetime(2026, 6, 13, tzinfo=UTC).timestamp() * 1000)
