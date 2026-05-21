"""Tests — `curiosity.tools.sibling_state_reader` (Task 3).

Validates:

1. None-store fallback returns empty SiblingState + logs (Q5 default).
2. Missing customer_id raises (cross-tenant guard).
3. Happy path: aws_account_region + finding_aggregate entities
   project to RegionState[] correctly.
4. Region with no finding_aggregate gets days_since=-1 sentinel.
5. Multi-region aggregation across asset counts + total_findings_30d.
6. SiblingState.any_data_present property.
7. Forgiving on malformed property values (missing keys, wrong types).
8. Cross-tenant isolation: reader scoped to customer_id only.
9. Freshest-sample-per-region: when multiple finding_aggregate rows
   exist for the same region, picks the one with smallest days_since.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from charter.memory.semantic import EntityRow, SemanticStore
from curiosity.tools.sibling_state_reader import (
    RegionState,
    SiblingState,
    read_sibling_state,
)


def _row(
    *,
    entity_type: str,
    external_id: str,
    properties: dict[str, Any],
    tenant_id: str = "acme",
) -> EntityRow:
    return EntityRow(
        entity_id=f"ent_{external_id}",
        tenant_id=tenant_id,
        entity_type=entity_type,
        external_id=external_id,
        properties=properties,
        created_at=datetime(2026, 5, 21, 12, 0, tzinfo=UTC),
    )


def _make_store(rows_by_type: dict[str, list[EntityRow]]) -> SemanticStore:
    """Return an AsyncMock(spec=SemanticStore) whose list_entities_by_type
    dispatches on entity_type."""

    async def fake_list(*, tenant_id: str, entity_type: str) -> list[EntityRow]:
        del tenant_id  # tenant scoping is verified separately
        return list(rows_by_type.get(entity_type, []))

    store = AsyncMock(spec=SemanticStore)
    store.list_entities_by_type.side_effect = fake_list
    return cast(SemanticStore, store)


# ---------------------------------------------------------------------------
# Q5 None-store fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_none_store_returns_empty_state(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="curiosity.tools.sibling_state_reader"):
        state = await read_sibling_state(None, customer_id="acme")
    assert state == SiblingState()
    assert any("semantic_store=None" in rec.message for rec in caplog.records)


@pytest.mark.asyncio
async def test_none_store_any_data_present_is_false() -> None:
    state = await read_sibling_state(None, customer_id="acme")
    assert state.any_data_present is False


# ---------------------------------------------------------------------------
# Tenant guard
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_customer_id_raises_value_error() -> None:
    with pytest.raises(ValueError, match="customer_id"):
        await read_sibling_state(None, customer_id="")


@pytest.mark.asyncio
async def test_customer_id_passed_through_to_store() -> None:
    """Verify tenant scoping reaches the SemanticStore call."""
    store = _make_store({})
    await read_sibling_state(store, customer_id="customer-X")
    # The fake_list above strips tenant_id, but the AsyncMock records the call.
    for call in store.list_entities_by_type.await_args_list:
        assert call.kwargs["tenant_id"] == "customer-X"


# ---------------------------------------------------------------------------
# Happy path — region inventory + finding aggregates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_projects_region_and_finding_aggregates() -> None:
    store = _make_store(
        {
            "aws_account_region": [
                _row(
                    entity_type="aws_account_region",
                    external_id="us-east-1",
                    properties={"asset_count": 42},
                ),
                _row(
                    entity_type="aws_account_region",
                    external_id="eu-west-3",
                    properties={"asset_count": 17},
                ),
            ],
            "finding_aggregate": [
                _row(
                    entity_type="finding_aggregate",
                    external_id="us-east-1:f3",
                    properties={
                        "region": "us-east-1",
                        "days_since_last_finding": 2,
                        "last_finding_severity": "high",
                        "source_agent": "cloud_posture",
                    },
                ),
            ],
        }
    )
    state = await read_sibling_state(store, customer_id="acme")
    assert state.total_assets == 59
    regions = {r.region: r for r in state.regions}
    assert regions["us-east-1"].days_since_last_finding == 2
    assert regions["us-east-1"].last_finding_severity == "high"


@pytest.mark.asyncio
async def test_region_without_finding_aggregate_gets_sentinel() -> None:
    """A region with assets but no findings ever -> days_since=-1."""
    store = _make_store(
        {
            "aws_account_region": [
                _row(
                    entity_type="aws_account_region",
                    external_id="ap-south-1",
                    properties={"asset_count": 12},
                ),
            ],
            "finding_aggregate": [],  # explicitly empty
        }
    )
    state = await read_sibling_state(store, customer_id="acme")
    assert len(state.regions) == 1
    region = state.regions[0]
    assert region.days_since_last_finding == -1
    assert region.last_finding_severity is None


# ---------------------------------------------------------------------------
# Multi-region aggregation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_region_totals_aggregate() -> None:
    store = _make_store(
        {
            "aws_account_region": [
                _row(
                    entity_type="aws_account_region",
                    external_id="us-east-1",
                    properties={"asset_count": 10},
                ),
                _row(
                    entity_type="aws_account_region",
                    external_id="eu-west-3",
                    properties={"asset_count": 25},
                ),
                _row(
                    entity_type="aws_account_region",
                    external_id="ap-south-1",
                    properties={"asset_count": 5},
                ),
            ],
            "finding_aggregate": [
                _row(
                    entity_type="finding_aggregate",
                    external_id="us-east-1:f3",
                    properties={
                        "region": "us-east-1",
                        "days_since_last_finding": 1,
                    },
                ),
                _row(
                    entity_type="finding_aggregate",
                    external_id="eu-west-3:d5",
                    properties={
                        "region": "eu-west-3",
                        "days_since_last_finding": 14,
                    },
                ),
            ],
        }
    )
    state = await read_sibling_state(store, customer_id="acme", window_days=30)
    assert state.total_assets == 40
    assert state.total_findings_30d == 2  # both within the 30-day window
    assert len(state.regions) == 3


@pytest.mark.asyncio
async def test_findings_outside_window_not_counted() -> None:
    """Findings older than window_days do NOT count toward total_findings_30d."""
    store = _make_store(
        {
            "aws_account_region": [
                _row(
                    entity_type="aws_account_region",
                    external_id="us-east-1",
                    properties={"asset_count": 10},
                ),
            ],
            "finding_aggregate": [
                _row(
                    entity_type="finding_aggregate",
                    external_id="us-east-1:f3",
                    properties={
                        "region": "us-east-1",
                        "days_since_last_finding": 100,  # outside 30d
                    },
                ),
            ],
        }
    )
    state = await read_sibling_state(store, customer_id="acme", window_days=30)
    assert state.total_findings_30d == 0


# ---------------------------------------------------------------------------
# Freshest-sample-per-region
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multiple_aggregates_per_region_picks_freshest() -> None:
    """If multiple finding_aggregate rows exist for the same region
    (e.g. one per source-agent), the reader picks the row with the
    smallest days_since — the freshest sample of activity."""
    store = _make_store(
        {
            "aws_account_region": [
                _row(
                    entity_type="aws_account_region",
                    external_id="us-east-1",
                    properties={"asset_count": 30},
                ),
            ],
            "finding_aggregate": [
                _row(
                    entity_type="finding_aggregate",
                    external_id="us-east-1:f3",
                    properties={
                        "region": "us-east-1",
                        "days_since_last_finding": 15,
                        "last_finding_severity": "low",
                    },
                ),
                _row(
                    entity_type="finding_aggregate",
                    external_id="us-east-1:d5",
                    properties={
                        "region": "us-east-1",
                        "days_since_last_finding": 3,
                        "last_finding_severity": "high",
                    },
                ),
            ],
        }
    )
    state = await read_sibling_state(store, customer_id="acme")
    assert len(state.regions) == 1
    assert state.regions[0].days_since_last_finding == 3
    assert state.regions[0].last_finding_severity == "high"


# ---------------------------------------------------------------------------
# Forgiving on malformed property values
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_malformed_properties_default_to_zero() -> None:
    """Properties with wrong types are silently coerced — never raises."""
    store = _make_store(
        {
            "aws_account_region": [
                _row(
                    entity_type="aws_account_region",
                    external_id="us-east-1",
                    properties={"asset_count": "not-an-int"},  # malformed
                ),
            ],
            "finding_aggregate": [
                _row(
                    entity_type="finding_aggregate",
                    external_id="us-east-1:f3",
                    properties={
                        "region": "us-east-1",
                        "days_since_last_finding": None,  # malformed
                    },
                ),
            ],
        }
    )
    state = await read_sibling_state(store, customer_id="acme")
    assert state.regions[0].asset_count == 0  # coerced from "not-an-int"
    assert state.regions[0].days_since_last_finding == 0  # coerced from None


@pytest.mark.asyncio
async def test_finding_aggregate_without_region_skipped() -> None:
    """Aggregate row with no 'region' property is silently dropped."""
    store = _make_store(
        {
            "aws_account_region": [
                _row(
                    entity_type="aws_account_region",
                    external_id="us-east-1",
                    properties={"asset_count": 10},
                ),
            ],
            "finding_aggregate": [
                _row(
                    entity_type="finding_aggregate",
                    external_id="orphan",
                    properties={"days_since_last_finding": 5},  # no region key
                ),
            ],
        }
    )
    state = await read_sibling_state(store, customer_id="acme")
    # region us-east-1 falls back to sentinel since orphan aggregate is dropped
    assert state.regions[0].days_since_last_finding == -1


# ---------------------------------------------------------------------------
# SiblingState.any_data_present
# ---------------------------------------------------------------------------


def test_any_data_present_false_for_empty_state() -> None:
    assert SiblingState().any_data_present is False


def test_any_data_present_true_with_regions() -> None:
    state = SiblingState(
        regions=(
            RegionState(
                region="us-east-1",
                asset_count=10,
                days_since_last_finding=5,
                last_finding_severity="medium",
            ),
        ),
        total_assets=10,
    )
    assert state.any_data_present is True


# ---------------------------------------------------------------------------
# Both entity-type queries made
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reader_queries_both_entity_types() -> None:
    """Reader must call list_entities_by_type for both
    aws_account_region and finding_aggregate (even when results are
    empty)."""
    store = _make_store({})
    await read_sibling_state(store, customer_id="acme")
    queried_types = {
        call.kwargs["entity_type"] for call in store.list_entities_by_type.await_args_list
    }
    assert queried_types == {"aws_account_region", "finding_aggregate"}
