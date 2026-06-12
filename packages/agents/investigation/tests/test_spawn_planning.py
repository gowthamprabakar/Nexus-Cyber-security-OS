"""investigation v0.2 Task 9 — spawn-batch planning + allowlist tests (WI-I11/WI-I15)."""

from __future__ import annotations

import pytest
from investigation.subinvestigations.spawn_planning import (
    only_investigation_spawns,
    plan_spawn_batches,
)


def test_batches_under_cap() -> None:
    assert plan_spawn_batches(4) == (4,)


def test_batches_at_cap() -> None:
    assert plan_spawn_batches(5) == (5,)


def test_batches_over_cap_split() -> None:
    assert plan_spawn_batches(7) == (5, 2)
    assert plan_spawn_batches(10) == (5, 5)
    assert plan_spawn_batches(13) == (5, 5, 3)


def test_zero_workers() -> None:
    assert plan_spawn_batches(0) == ()


def test_no_batch_exceeds_cap() -> None:
    for n in range(0, 30):
        assert all(b <= 5 for b in plan_spawn_batches(n))


def test_negative_rejected() -> None:
    with pytest.raises(ValueError, match="worker_count"):
        plan_spawn_batches(-1)


def test_custom_cap() -> None:
    assert plan_spawn_batches(5, parallel_cap=2) == (2, 2, 1)


def test_allowlist_only_investigation() -> None:
    # WI-I15: only 'investigation' may spawn workers.
    assert only_investigation_spawns() is True
