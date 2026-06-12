"""synthesis v0.2 Task 2 — OCSF 2004 schema tests (Q1/WI-Y5)."""

from __future__ import annotations

from synthesis.ocsf.schema import (
    OCSF_CLASS_UID,
    build_synthesis_finding,
    severity_to_id,
)


def _finding(**kw: object) -> dict:
    base: dict = {
        "finding_id": "SYN-001",
        "title": "Fleet posture narrative",
        "narrative_markdown": "## Summary\n`CSPM-AWS-S3-001` is public.",
        "executive_summary": "One public bucket.",
        "severity": "high",
        "source_finding_ids": ("CSPM-AWS-S3-001",),
        "detected_at_ms": 1_700_000_000_000,
    }
    base.update(kw)
    return build_synthesis_finding(**base)  # type: ignore[arg-type]


def test_class_uid_is_2004() -> None:
    assert _finding()["class_uid"] == OCSF_CLASS_UID == 2004
    assert _finding()["category_uid"] == 2


def test_narrative_in_unmapped_slot() -> None:
    # Q1: the markdown narrative rides in the unmapped slot (the F.6 precedent).
    unmapped = _finding()["unmapped"]
    assert "## Summary" in unmapped["narrative_markdown"]
    assert unmapped["executive_summary"] == "One public bucket."
    assert unmapped["source_finding_ids"] == ["CSPM-AWS-S3-001"]


def test_severity_mapping() -> None:
    assert severity_to_id("critical") == 5 and severity_to_id("informational") == 1
    assert _finding(severity="high")["severity_id"] == 4
    assert _finding(severity="bogus")["severity_id"] == 1  # unknown -> Informational


def test_finding_info_carries_id_and_title() -> None:
    fi = _finding()["finding_info"]
    assert fi["uid"] == "SYN-001" and fi["title"] == "Fleet posture narrative"
    assert fi["types"] == ["narrative_synthesis"]


def test_type_uid_and_metadata() -> None:
    f = _finding()
    assert f["type_uid"] == 2004 * 100 + 1
    assert f["metadata"]["product"]["name"] == "Nexus Synthesis"
    assert f["metadata"]["version"] == "1.3.0"


def test_deterministic_byte_identical() -> None:
    # WI-Y5: same narrative input -> byte-identical OCSF payload.
    assert _finding() == _finding()


def test_source_ids_sorted() -> None:
    f = _finding(source_finding_ids=("b-2", "a-1", "c-3"))
    assert f["unmapped"]["source_finding_ids"] == ["a-1", "b-2", "c-3"]
