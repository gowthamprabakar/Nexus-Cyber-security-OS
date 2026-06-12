"""curiosity v0.2 Task 2 — OCSF 2004 schema tests (Q1/WI-X5)."""

from __future__ import annotations

from curiosity.ocsf.schema import (
    OCSF_CLASS_UID,
    build_curiosity_finding,
    severity_to_id,
)


def _finding() -> dict:
    return build_curiosity_finding(
        claim_id="01HV0T0000000000000000CLM1",
        title="Coverage gap hypothesis: eu-west-1",
        statement="eu-west-1 may be under-scanned.",
        rationale="12 assets, no findings in 40 days.",
        severity="medium",
        coverage_gap_id="region:eu-west-1",
        probe_directive={"target_agent": "cloud_posture", "action": "scan"},
        detected_at_ms=1_700_000_000_000,
    )


def test_class_uid_is_2004() -> None:
    assert OCSF_CLASS_UID == 2004
    assert _finding()["class_uid"] == 2004


def test_severity_mapping() -> None:
    assert severity_to_id("critical") == 5
    assert severity_to_id("medium") == 3
    assert severity_to_id("bogus") == 1  # unknown -> Informational


def test_type_uid_derivation() -> None:
    assert _finding()["type_uid"] == 2004 * 100 + 1


def test_claim_payload_in_unmapped() -> None:
    unmapped = _finding()["unmapped"]
    assert unmapped["coverage_gap_id"] == "region:eu-west-1"
    assert unmapped["statement"] == "eu-west-1 may be under-scanned."
    assert unmapped["probe_directive"]["target_agent"] == "cloud_posture"


def test_finding_info_uid_is_claim_id() -> None:
    assert _finding()["finding_info"]["uid"] == "01HV0T0000000000000000CLM1"
    assert _finding()["finding_info"]["types"] == ["coverage_gap_hypothesis"]


def test_deterministic_byte_identical() -> None:
    import json

    assert json.dumps(_finding(), sort_keys=True) == json.dumps(_finding(), sort_keys=True)


def test_product_name() -> None:
    assert _finding()["metadata"]["product"]["name"] == "Nexus Curiosity"
