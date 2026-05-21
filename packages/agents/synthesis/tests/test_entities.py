"""Tests — ``synthesis.entities`` (Task 8 half).

Validates the ``SynthesisReportEntity`` pydantic model: construction,
external_id derivation, properties serialisation, validation guards.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from synthesis.entities import SynthesisReportEntity


def _now() -> datetime:
    return datetime(2026, 5, 21, 12, 0, tzinfo=UTC)


def _entity(**overrides: object) -> SynthesisReportEntity:
    defaults: dict[str, object] = {
        "customer_id": "acme",
        "run_id": "run-2026-05-21-001",
        "section_count": 4,
        "executive_summary_paragraph": (
            "The 2026-05-21 scan window surfaced two high-severity findings."
        ),
        "total_cited_findings": 7,
        "scan_started_at": _now(),
        "scan_completed_at": datetime(2026, 5, 21, 12, 5, tzinfo=UTC),
        "review_retries": 0,
    }
    defaults.update(overrides)
    return SynthesisReportEntity(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_entity_construction_and_round_trip() -> None:
    entity = _entity()
    assert entity.customer_id == "acme"
    assert entity.section_count == 4
    assert entity.review_retries == 0


def test_external_id_is_customer_run_pair() -> None:
    entity = _entity(customer_id="contoso", run_id="r1")
    assert entity.external_id == "contoso:r1"


def test_properties_includes_all_persisted_fields() -> None:
    entity = _entity()
    props = entity.properties()

    assert props["customer_id"] == "acme"
    assert props["run_id"] == "run-2026-05-21-001"
    assert props["section_count"] == 4
    assert "high-severity" in props["executive_summary_paragraph"]
    assert props["total_cited_findings"] == 7
    assert props["review_retries"] == 0
    # Timestamps must serialise to ISO-8601 strings so SemanticStore
    # JSON column survives the round-trip without datetime coercion.
    assert "T" in props["scan_started_at"]
    assert "T" in props["scan_completed_at"]


def test_entity_is_frozen() -> None:
    """ConfigDict(frozen=True) — mutation attempts raise."""
    entity = _entity()
    with pytest.raises((TypeError, ValidationError)):
        entity.section_count = 99  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Validation guards
# ---------------------------------------------------------------------------


def test_empty_customer_id_rejected() -> None:
    with pytest.raises(ValidationError, match="at least 1 character"):
        _entity(customer_id="")


def test_empty_run_id_rejected() -> None:
    with pytest.raises(ValidationError, match="at least 1 character"):
        _entity(run_id="")


def test_negative_section_count_rejected() -> None:
    with pytest.raises(ValidationError):
        _entity(section_count=-1)


def test_negative_review_retries_rejected() -> None:
    with pytest.raises(ValidationError):
        _entity(review_retries=-1)


def test_executive_summary_paragraph_max_length() -> None:
    """Paragraph max_length=2000 mirrors ExecutiveSummary schema."""
    with pytest.raises(ValidationError):
        _entity(executive_summary_paragraph="x" * 2001)
