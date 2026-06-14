"""Tests — Track D D-2 continuous-mode metrics (inert counter surface)."""

from __future__ import annotations

import pytest
from supervisor.continuous_metrics import ContinuousMetrics


def test_fresh_metrics_are_zero() -> None:
    """Inert default: a constructed counter (empty driver → no ticks) is all-zero."""
    m = ContinuousMetrics()
    snap = m.snapshot()
    assert snap["ticks"] == 0
    assert snap["due_runs_dispatched"] == 0
    assert snap["dispatch_errors"] == 0
    assert snap["error_rate"] == 0.0
    assert snap["per_tenant_cadence"] == {}


def test_record_tick_and_dispatch() -> None:
    m = ContinuousMetrics()
    m.record_tick()
    m.record_tick()
    m.record_dispatch(3)
    assert m.snapshot()["ticks"] == 2
    assert m.snapshot()["due_runs_dispatched"] == 3


def test_error_rate() -> None:
    m = ContinuousMetrics()
    m.record_dispatch(3)
    m.record_error(1)
    assert m.error_rate() == pytest.approx(0.25)


def test_error_rate_zero_when_no_attempts() -> None:
    assert ContinuousMetrics().error_rate() == 0.0


def test_set_cadence_labels() -> None:
    m = ContinuousMetrics()
    m.set_cadence("acme", "weekly")
    m.set_cadence("globex", "daily")
    assert m.snapshot()["per_tenant_cadence"] == {"acme": "weekly", "globex": "daily"}


def test_negative_counts_rejected() -> None:
    m = ContinuousMetrics()
    with pytest.raises(ValueError, match="dispatch count must be >= 0"):
        m.record_dispatch(-1)
    with pytest.raises(ValueError, match="error count must be >= 0"):
        m.record_error(-1)


def test_snapshot_is_json_serializable() -> None:
    import json

    m = ContinuousMetrics()
    m.record_tick()
    m.set_cadence("acme", "monthly")
    json.dumps(m.snapshot())  # must not raise
