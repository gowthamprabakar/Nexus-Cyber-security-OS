"""Tests — Track D D-2 continuous status-page stub (read-only aggregator)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from supervisor.continuous_metrics import ContinuousMetrics
from supervisor.freshness import record_run
from supervisor.status_page import build_continuous_status


def test_status_is_inert_defaults(tmp_path: Path) -> None:
    """No cadence, no freshness, fresh metrics → all-empty/zero, JSON-serializable."""
    status = build_continuous_status(tmp_path, customer_id="acme")
    assert status["customer_id"] == "acme"
    assert status["cadence"] is None
    assert status["freshness"] == {}
    assert status["metrics"]["ticks"] == 0
    json.dumps(status)  # must not raise


def test_status_composes_all_three_surfaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEXUS_CONTINUOUS_CADENCE", "weekly")
    record_run(
        tmp_path,
        agent_id="cloud_posture",
        customer_id="acme",
        at=datetime(2026, 6, 14, tzinfo=UTC),
    )
    metrics = ContinuousMetrics()
    metrics.record_tick()

    status = build_continuous_status(tmp_path, customer_id="acme", metrics=metrics)

    assert status["cadence"] == "weekly"
    assert "cloud_posture" in status["freshness"]
    assert status["metrics"]["ticks"] == 1


def test_status_is_per_tenant(tmp_path: Path) -> None:
    record_run(tmp_path, agent_id="identity", customer_id="acme")
    status = build_continuous_status(tmp_path, customer_id="globex")
    assert status["freshness"] == {}  # acme's data not visible to globex
