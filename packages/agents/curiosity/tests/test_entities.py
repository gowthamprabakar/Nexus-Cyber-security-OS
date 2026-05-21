"""Tests — `curiosity.entities` (Task 8 half).

Validates the HypothesisEntity pydantic model.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from curiosity.entities import HypothesisEntity
from pydantic import ValidationError

_VALID_ULID = "01J7M3X9Z1K8RPVQNH2T8DBHFZ"


def _entity(**overrides: object) -> HypothesisEntity:
    defaults: dict[str, object] = {
        "customer_id": "acme",
        "run_id": "run-2026-05-21-001",
        "hypothesis_idx": 0,
        "claim_id": _VALID_ULID,
        "statement": "Region us-east-1 appears under-scanned.",
        "target_agent": "data_security",
        "cited_region": "us-east-1",
        "emitted_at": datetime(2026, 5, 21, 12, 0, tzinfo=UTC),
    }
    defaults.update(overrides)
    return HypothesisEntity(**defaults)  # type: ignore[arg-type]


def test_entity_construction_and_round_trip() -> None:
    entity = _entity()
    assert entity.customer_id == "acme"
    assert entity.hypothesis_idx == 0
    assert entity.claim_id == _VALID_ULID


def test_external_id_is_customer_run_idx_triple() -> None:
    entity = _entity(customer_id="contoso", run_id="r1", hypothesis_idx=3)
    assert entity.external_id == "contoso:r1:3"


def test_properties_includes_all_persisted_fields() -> None:
    entity = _entity()
    props = entity.properties()

    assert props["customer_id"] == "acme"
    assert props["run_id"] == "run-2026-05-21-001"
    assert props["hypothesis_idx"] == 0
    assert props["claim_id"] == _VALID_ULID
    assert "under-scanned" in props["statement"]
    assert props["target_agent"] == "data_security"
    assert props["cited_region"] == "us-east-1"
    # Timestamps serialise to ISO-8601 strings so SemanticStore's JSON
    # column survives the round-trip.
    assert "T" in props["emitted_at"]


def test_entity_is_frozen() -> None:
    entity = _entity()
    with pytest.raises((TypeError, ValidationError)):
        entity.statement = "mutated"  # type: ignore[misc]


def test_empty_customer_id_rejected() -> None:
    with pytest.raises(ValidationError, match="at least 1 character"):
        _entity(customer_id="")


def test_empty_run_id_rejected() -> None:
    with pytest.raises(ValidationError, match="at least 1 character"):
        _entity(run_id="")


def test_negative_hypothesis_idx_rejected() -> None:
    with pytest.raises(ValidationError):
        _entity(hypothesis_idx=-1)


def test_malformed_claim_id_rejected() -> None:
    """26-char string that isn't valid Crockford base32."""
    with pytest.raises(ValidationError, match="ULID"):
        _entity(claim_id="OOOOOOOOOOOOOOOOOOOOOOOOOO")


def test_statement_max_length_enforced() -> None:
    with pytest.raises(ValidationError):
        _entity(statement="x" * 401)


def test_empty_target_agent_rejected() -> None:
    with pytest.raises(ValidationError):
        _entity(target_agent="")


def test_empty_cited_region_rejected() -> None:
    with pytest.raises(ValidationError):
        _entity(cited_region="")
