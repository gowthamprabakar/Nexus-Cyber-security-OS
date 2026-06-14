"""Tests — Track D D-2 freshness-signal API (inert read surface + v0.4 write)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from supervisor.freshness import (
    FreshnessStoreError,
    all_freshness,
    freshness_path,
    last_refreshed,
    record_run,
)

_AT = datetime(2026, 6, 14, 12, 0, 0, tzinfo=UTC)


def test_last_refreshed_none_when_no_file(tmp_path: Path) -> None:
    """Inert default: nothing written yet → None."""
    assert last_refreshed(tmp_path, agent_id="cloud_posture", customer_id="acme") is None


def test_record_then_read_round_trip(tmp_path: Path) -> None:
    record_run(tmp_path, agent_id="cloud_posture", customer_id="acme", at=_AT)
    got = last_refreshed(tmp_path, agent_id="cloud_posture", customer_id="acme")
    assert got == _AT


def test_record_is_idempotent_upsert(tmp_path: Path) -> None:
    record_run(tmp_path, agent_id="cloud_posture", customer_id="acme", at=_AT)
    later = datetime(2026, 6, 15, 9, 0, 0, tzinfo=UTC)
    record_run(tmp_path, agent_id="cloud_posture", customer_id="acme", at=later)
    assert last_refreshed(tmp_path, agent_id="cloud_posture", customer_id="acme") == later


def test_missing_agent_entry_is_none(tmp_path: Path) -> None:
    record_run(tmp_path, agent_id="cloud_posture", customer_id="acme", at=_AT)
    assert last_refreshed(tmp_path, agent_id="identity", customer_id="acme") is None


def test_all_freshness_returns_every_entry(tmp_path: Path) -> None:
    record_run(tmp_path, agent_id="cloud_posture", customer_id="acme", at=_AT)
    record_run(tmp_path, agent_id="identity", customer_id="acme", at=_AT)
    everything = all_freshness(tmp_path, customer_id="acme")
    assert set(everything) == {"cloud_posture", "identity"}


def test_per_tenant_isolation(tmp_path: Path) -> None:
    record_run(tmp_path, agent_id="cloud_posture", customer_id="acme", at=_AT)
    assert last_refreshed(tmp_path, agent_id="cloud_posture", customer_id="globex") is None


def test_malformed_file_raises(tmp_path: Path) -> None:
    path = freshness_path(tmp_path, "acme")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not json{", encoding="utf-8")
    with pytest.raises(FreshnessStoreError, match="malformed JSON"):
        last_refreshed(tmp_path, agent_id="cloud_posture", customer_id="acme")
