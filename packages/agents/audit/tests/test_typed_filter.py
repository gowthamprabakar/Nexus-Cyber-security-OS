"""audit v0.2 Task 9 — broad typed query filter tests (Q3)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from audit.query.typed_filter import TypedAuditFilter, parse_filter
from pydantic import ValidationError

_TENANT = "01HV0T0000000000000000TENA"


def test_parse_minimal_tenant_only() -> None:
    f = parse_filter({"tenant_id": _TENANT})
    assert f.tenant_id == _TENANT and f.action is None and f.status is None


def test_parse_all_five_dimensions() -> None:
    f = parse_filter(
        {
            "tenant_id": _TENANT,
            "since": "2026-05-01T00:00:00Z",
            "until": "2026-05-02T00:00:00Z",
            "action": "scan",
            "agent_id": "cloud_posture",
            "status": "success",
        }
    )
    assert f.action == "scan" and f.agent_id == "cloud_posture" and f.status == "success"
    assert f.since == datetime(2026, 5, 1, tzinfo=UTC)


def test_since_after_until_rejected() -> None:
    with pytest.raises(ValidationError, match="since must be <= until"):
        parse_filter(
            {
                "tenant_id": _TENANT,
                "since": "2026-05-02T00:00:00Z",
                "until": "2026-05-01T00:00:00Z",
            }
        )


def test_missing_tenant_rejected() -> None:
    with pytest.raises(ValidationError):
        parse_filter({"action": "scan"})


def test_short_tenant_rejected() -> None:
    with pytest.raises(ValidationError):
        parse_filter({"tenant_id": "short"})


def test_extra_field_forbidden() -> None:
    with pytest.raises(ValidationError):
        parse_filter({"tenant_id": _TENANT, "bogus": "x"})


def test_filter_is_frozen() -> None:
    f = parse_filter({"tenant_id": _TENANT})
    with pytest.raises(ValidationError):
        f.action = "scan"  # type: ignore[misc]


def test_single_tenant_not_cross_tenant() -> None:
    assert parse_filter({"tenant_id": _TENANT}).is_cross_tenant() is False


def test_status_dimension_carried() -> None:
    assert parse_filter({"tenant_id": _TENANT, "status": "failure"}).status == "failure"


def test_construct_directly() -> None:
    f = TypedAuditFilter(tenant_id=_TENANT, action="emit")
    assert f.action == "emit"
